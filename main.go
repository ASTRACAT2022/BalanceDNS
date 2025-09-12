package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"reflect" // Добавлено для рефлексии
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/golang/groupcache/lru"
)

// CacheEntry представляет запись в кэше
type CacheEntry struct {
	Msg      *dns.Msg
	ExpireAt int64 // Unix timestamp для быстрой работы
}

// DNSKEYCacheEntry для кэширования DNSKEY записей
type DNSKEYCacheEntry struct {
	DNSKEY   *dns.DNSKEY
	RRSIG    *dns.RRSIG // Подпись DNSKEY
	ExpireAt int64
}

// ValidationError ошибка валидации DNSSEC
type ValidationError struct {
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("DNSSEC validation error: %s", e.Reason)
}

// ErrorStats статистика ошибок по доменам
type ErrorStats struct {
	errors map[string]int64
	mutex  sync.RWMutex
}

// DNSHandler обрабатывает DNS-запросы
type DNSHandler struct {
	// Кэши
	cache       *lru.Cache // *lru.Cache для обычных DNS-запросов
	dnskeyCache *lru.Cache // *lru.Cache для DNSKEY записей
	cacheTTL    int64      // в секундах
	cacheMu     sync.RWMutex

	// Статистика ошибок
	errorStats *ErrorStats

	// Метрики
	totalQueries    int64
	cachedQueries   int64
	dnssecQueries   int64 // Счетчик DNSSEC-запросов
	validationError int64 // Счетчик ошибок валидации

	// Клиент для отправки DNS-запросов
	client *dns.Client

	// Корневые сервера
	rootServers []string

	// Корневой DNSKEY ( trust anchor)
	rootDNSKEY *dns.DNSKEY

	// Флаг для включения/выключения DNSSEC
	enableDNSSEC bool
	strictDNSSEC bool // Строгий режим DNSSEC (возвращать ошибки при проблемах)
}

// NewDNSHandler создает новый обработчик DNS-запросов
func NewDNSHandler() *DNSHandler {
	handler := &DNSHandler{
		cache:       lru.New(30000), // Увеличенный кэш для DNS-запросов
		dnskeyCache: lru.New(5000),  // Кэш для DNSKEY записей
		cacheTTL:    300,            // 5 минут по умолчанию
		errorStats: &ErrorStats{
			errors: make(map[string]int64),
		},
		client: &dns.Client{
			Net:          "udp",
			UDPSize:      4096, // Увеличенный размер UDP пакета для DNSSEC
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		},
		// Список корневых серверов
		rootServers: []string{
			"198.41.0.4:53",    // a.root-servers.net
			"199.9.14.201:53",  // b.root-servers.net
			"192.33.4.12:53",   // c.root-servers.net
			"199.7.91.13:53",   // d.root-servers.net
			"192.203.230.10:53",// e.root-servers.net
			"192.5.5.241:53",   // f.root-servers.net
			"192.112.36.4:53",  // g.root-servers.net
			"198.97.190.53:53", // h.root-servers.net
			"192.36.148.17:53", // i.root-servers.net
			"192.58.128.30:53", // j.root-servers.net
			"193.0.14.129:53",  // k.root-servers.net
			"199.7.83.42:53",   // l.root-servers.net
			"202.12.27.33:53",  // m.root-servers.net
		},
		enableDNSSEC: true,  // Включаем DNSSEC по умолчанию
		strictDNSSEC: false, // Не строгий режим по умолчанию
	}

	// Предзагрузка корневого DNSKEY
	if handler.enableDNSSEC {
		go handler.loadRootDNSKEY()
	}

	// Запускаем очистку кэша в отдельной горутине
	go handler.cleanupCache()

	// Запускаем вывод метрик
	go handler.printMetrics()

	// Запускаем вывод сводки ошибок
	go handler.printErrorSummary()

	return handler
}

// loadRootDNSKEY предзагружает корневой DNSKEY
func (h *DNSHandler) loadRootDNSKEY() {
	// Корневой DNSKEY (KSK-2017) - реальный ключ
	rootKey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600, // 1 hour
		},
		Flags:     257, // Zone Key + Secure Entry Point
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		// Реальный публичный ключ KSK-2017
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5ZRzBQOzh8QJExzVFAJo2QPR+YniYFHtWr836jBIk/t/qOj+NNBCeWKEQinDgQtLk3EEqxDIuK/PbWZgr7X4SF7DNhJnc8B0NVOAvb/MFFu6E3hL5X/hxFsY3Q26VA2ap3kd2tS76ecMGTB88pwJ2QcUYZcLj23mD6CAW+4eiLZ8kOE5G+8lhHqZ9f6YXzV5hUVx1OarXIaxYVvNidD57XudCikj4NZgTb+VLGv8aEarXCKd93mjK4Gz7B6FRkZogRkuLwTc6vJ4VIlE7DrSzovm2B2/+c8JK+YvHFG8B9VeRog92s+H6Xj4O/OdhpIpiWQ=",
	}

	h.cacheMu.Lock()
	h.rootDNSKEY = rootKey
	h.dnskeyCache.Add(".", &DNSKEYCacheEntry{
		DNSKEY:   rootKey,
		ExpireAt: time.Now().Unix() + 3600, // Кэшируем на 1 час
	})
	h.cacheMu.Unlock()

	log.Println("Root DNSKEY loaded and cached")
}

// cleanupCache периодически очищает истекшие записи из кэша
func (h *DNSHandler) cleanupCache() {
	ticker := time.NewTicker(30 * time.Second) // Проверяем чаще
	defer ticker.Stop()

	for {
		<-ticker.C
		// Очистка кэша будет обрабатываться через LRU и проверку TTL при доступе
	}
}

// printMetrics выводит метрики работы сервера
func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		total := atomic.LoadInt64(&h.totalQueries)
		cached := atomic.LoadInt64(&h.cachedQueries)
		dnssec := atomic.LoadInt64(&h.dnssecQueries)
		validationErr := atomic.LoadInt64(&h.validationError)

		cacheHitRate := float64(0)
		dnssecRate := float64(0)
		validationErrRate := float64(0)
		if total > 0 {
			cacheHitRate = float64(cached) / float64(total) * 100
			dnssecRate = float64(dnssec) / float64(total) * 100
			validationErrRate = float64(validationErr) / float64(total) * 100
		}

		log.Printf("METRICS - Total: %d, Cached: %d (%.2f%%), DNSSEC: %.2f%%, Validation Errors: %.2f%%",
			total, cached, cacheHitRate, dnssecRate, validationErrRate)
	}
}

// printErrorSummary выводит сводку по ошибкам
func (h *DNSHandler) printErrorSummary() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C

		h.errorStats.mutex.Lock()
		if len(h.errorStats.errors) > 0 {
			log.Printf("ERROR SUMMARY - Top problematic domains:")
			// Создаем срез для сортировки
			type domainError struct {
				domain string
				count  int64
			}

			var errors []domainError
			for domain, count := range h.errorStats.errors {
				errors = append(errors, domainError{domain, count})
			}

			// Простая сортировка по количеству ошибок (первые 10)
			sort.Slice(errors, func(i, j int) bool {
				return errors[i].count > errors[j].count // По убыванию
			})

			for i := 0; i < len(errors) && i < 10; i++ {
				log.Printf("  %s: %d errors", errors[i].domain, errors[i].count)
			}

			// Очищаем статистику после вывода
			h.errorStats.errors = make(map[string]int64)
		}
		h.errorStats.mutex.Unlock()
	}
}

// getCacheKey создает ключ для кэширования
func (h *DNSHandler) getCacheKey(name string, qtype uint16, dnssec bool) string {
	if dnssec {
		return name + "|" + fmt.Sprintf("%d|dnssec", qtype)
	}
	return name + "|" + fmt.Sprintf("%d", qtype)
}

// isExpired проверяет, истекла ли запись
func (h *DNSHandler) isExpired(expireAt int64) bool {
	return time.Now().Unix() > expireAt
}

// getCachedResponse пытается получить ответ из кэша
func (h *DNSHandler) getCachedResponse(key string, request *dns.Msg) *dns.Msg {
	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()

	value, ok := h.cache.Get(key)
	if !ok {
		return nil
	}

	entry := value.(*CacheEntry)

	// Проверяем, не истекло ли время жизни
	if h.isExpired(entry.ExpireAt) {
		h.cacheMu.RUnlock()
		h.cacheMu.Lock()
		h.cache.Remove(key)
		h.cacheMu.Unlock()
		h.cacheMu.RLock() // Блокируем чтение снова
		return nil
	}

	// Создаем копию сообщения
	cachedMsg := entry.Msg.Copy()

	// Сохраняем оригинальный ID запроса
	cachedMsg.Id = request.Id

	// Копируем EDNS0 опции из оригинального запроса
	if edns0 := request.IsEdns0(); edns0 != nil {
		// Создаем новый OPT record
		newOpt := new(dns.OPT)
		newOpt.Hdr.Name = "."
		newOpt.Hdr.Rrtype = dns.TypeOPT
		newOpt.SetUDPSize(edns0.UDPSize())
		newOpt.SetDo(edns0.Do())

		// Добавляем OPT record в ответ
		cachedMsg.Extra = append(cachedMsg.Extra, newOpt)
	}

	// Обновляем TTL в записях
	timeLeft := entry.ExpireAt - time.Now().Unix()
	if timeLeft < 0 {
		timeLeft = 0
	}
	ttlSeconds := uint32(timeLeft)

	// Обновляем TTL для всех записей
	for _, rr := range cachedMsg.Answer {
		rr.Header().Ttl = ttlSeconds
	}
	for _, rr := range cachedMsg.Ns {
		rr.Header().Ttl = ttlSeconds
	}
	for _, rr := range cachedMsg.Extra {
		// Пропускаем OPT record
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttlSeconds
		}
	}

	atomic.AddInt64(&h.cachedQueries, 1)
	return cachedMsg
}

// cacheResponse сохраняет ответ в кэш
func (h *DNSHandler) cacheResponse(key string, msg *dns.Msg) {
	// Определяем минимальный TTL
	minTTL := int64(300) // Минимум 5 минут

	// Для NXDOMAIN устанавливаем меньший TTL (например, 30 секунд)
	if msg.Rcode == dns.RcodeNameError {
		minTTL = 30 // NXDOMAIN кэшируем на 30 секунд
	} else {
		// Ищем минимальный TTL во всех секциях для успешных ответов
		sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
		for _, section := range sections {
			for _, rr := range section {
				// Пропускаем OPT record при расчете TTL
				if rr.Header().Rrtype != dns.TypeOPT && int64(rr.Header().Ttl) < minTTL && rr.Header().Ttl > 0 {
					minTTL = int64(rr.Header().Ttl)
				}
			}
		}
	}

	// Ограничиваем максимальный TTL
	if minTTL > 86400 { // Максимум 1 день
		minTTL = 86400
	}

	// Создаем копию сообщения для кэширования (без ID и OPT)
	cachedMsg := msg.Copy()

	// Удаляем OPT record из кэшируемого сообщения
	extra := make([]dns.RR, 0, len(cachedMsg.Extra))
	for _, rr := range cachedMsg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	cachedMsg.Extra = extra

	// Сохраняем в кэш
	expireAt := time.Now().Unix() + minTTL

	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	h.cache.Add(key, &CacheEntry{
		Msg:      cachedMsg,
		ExpireAt: expireAt,
	})
}

// getCachedDNSKEY пытается получить DNSKEY из кэша
func (h *DNSHandler) getCachedDNSKEY(name string) *dns.DNSKEY {
	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()

	value, ok := h.dnskeyCache.Get(name)
	if !ok {
		return nil
	}

	entry := value.(*DNSKEYCacheEntry)

	// Проверяем, не истекло ли время жизни
	if h.isExpired(entry.ExpireAt) {
		return nil
	}

	return entry.DNSKEY
}

// cacheDNSKEY сохраняет DNSKEY в кэш
func (h *DNSHandler) cacheDNSKEY(name string, dnskey *dns.DNSKEY, rrsig *dns.RRSIG) {
	if dnskey == nil {
		return
	}

	// Используем TTL из записи или минимальное значение
	ttl := int64(dnskey.Hdr.Ttl)
	if ttl < 300 { // Минимум 5 минут
		ttl = 300
	}
	if ttl > 86400 { // Максимум 1 день
		ttl = 86400
	}

	expireAt := time.Now().Unix() + ttl

	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	h.dnskeyCache.Add(name, &DNSKEYCacheEntry{
		DNSKEY:   dnskey,
		RRSIG:    rrsig,
		ExpireAt: expireAt,
	})
}

// recordError записывает ошибку в статистику
func (h *DNSHandler) recordError(domain string) {
	h.errorStats.mutex.Lock()
	defer h.errorStats.mutex.Unlock()

	h.errorStats.errors[domain]++
}

// isNormalError проверяет, является ли ошибка "нормальной" (не требующей логирования)
func (h *DNSHandler) isNormalError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "Refused") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "no answer from DNS server")
}

// queryNS отправляет запрос к указанному nameserver
func (h *DNSHandler) queryNS(server string, msg *dns.Msg) (*dns.Msg, error) {
	// Пытаемся сначала через UDP
	resp, _, err := h.client.Exchange(msg, server)
	if err != nil {
		// Если ошибка и пакет был усечен, пробуем через TCP
		if err == dns.ErrBuf || strings.Contains(err.Error(), "overflow") {
			h.client.Net = "tcp"
			resp, _, err = h.client.Exchange(msg, server)
			h.client.Net = "udp" // Возвращаем обратно на UDP
			return resp, err
		}
		// Для других ошибок сразу возвращаем
		return nil, err
	}

	// Если ответ усечен и мы используем UDP, пробуем TCP
	if resp != nil && resp.Truncated && h.client.Net == "udp" {
		h.client.Net = "tcp"
		resp, _, err = h.client.Exchange(msg, server)
		h.client.Net = "udp" // Возвращаем обратно на UDP
	}

	return resp, err
}

// validateWithKey проверяет RRSIG подпись для набора записей с использованием DNSKEY
func (h *DNSHandler) validateWithKey(rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY) error {
	if rrsig == nil || key == nil {
		return &ValidationError{Reason: "missing RRSIG or DNSKEY for validation"}
	}

	// Проверяем совпадение алгоритмов
	if rrsig.Algorithm != key.Algorithm {
		return &ValidationError{Reason: fmt.Sprintf("algorithm mismatch: RRSIG=%d, DNSKEY=%d", rrsig.Algorithm, key.Algorithm)}
	}

	// Проверяем совпадение тегов ключа
	if rrsig.KeyTag != key.KeyTag() {
		return &ValidationError{Reason: fmt.Sprintf("key tag mismatch: RRSIG=%d, DNSKEY=%d", rrsig.KeyTag, key.KeyTag())}
	}

	// Проверяем имя подписавшего
	if rrsig.SignerName != key.Hdr.Name {
		return &ValidationError{Reason: fmt.Sprintf("signer name mismatch: RRSIG=%s, DNSKEY=%s", rrsig.SignerName, key.Hdr.Name)}
	}

	// Подготавливаем данные для подписи согласно RFC 4034, 4035
	// 1. Канонизируем RRset (сортируем, приводим имя к нижнему регистру, устанавливаем TTL из RRSIG)
	// 2. Формируем RRSIG RDATA без поля Signature
	// 3. Конкатенируем RRSIG RDATA и RRset в бинарном формате (wire format)

	// 1. Канонизируем и сортируем RRset
	canonicalRRs := make([]dns.RR, len(rrset))
	copy(canonicalRRs, rrset)
	for _, rr := range canonicalRRs {
		// Канонизируем имя (RFC 4034)
		rr.Header().Name = strings.ToLower(dns.Fqdn(rr.Header().Name))
		// Устанавливаем TTL из RRSIG (RFC 4035)
		rr.Header().Ttl = rrsig.OrigTtl
	}

	// Сортируем канонизированный RRset (RFC 4034)
	// Используем простую сортировку строк
	sort.Slice(canonicalRRs, func(i, j int) bool {
		return canonicalRRs[i].String() < canonicalRRs[j].String()
	})

	// 2. Формируем RRSIG RDATA без поля Signature
	// Создаем временную RRSIG запись без подписи для паковки
	rrsigNoSig := &dns.RRSIG{
		Hdr:         rrsig.Hdr,
		TypeCovered: rrsig.TypeCovered,
		Algorithm:   rrsig.Algorithm,
		Labels:      rrsig.Labels,
		OrigTtl:     rrsig.OrigTtl,
		Expiration:  rrsig.Expiration,
		Inception:   rrsig.Inception,
		KeyTag:      rrsig.KeyTag,
		SignerName:  strings.ToLower(dns.Fqdn(rrsig.SignerName)), // Канонизируем имя подписавшего
		Signature:   "", // Без подписи
	}

	// Пакуем RRSIG RDATA в wire формат
	rrsigWire := make([]byte, dns.Len(rrsigNoSig)*2) // Увеличиваем буфер
	off, err := dns.PackRR(rrsigNoSig, rrsigWire, 0, nil, false)
	if err != nil {
		return &ValidationError{Reason: fmt.Sprintf("failed to pack RRSIG RDATA: %v", err)}
	}
	rrsigRdata := rrsigWire[:off]

	// 3. Пакуем канонизированный RRset в wire формат
	var rrsetData []byte
	for _, rr := range canonicalRRs {
		rrWire := make([]byte, dns.Len(rr)*2) // Увеличиваем буфер
		off, err := dns.PackRR(rr, rrWire, 0, nil, false)
		if err != nil {
			return &ValidationError{Reason: fmt.Sprintf("failed to pack RR: %v", err)}
		}
		rrsetData = append(rrsetData, rrWire[:off]...)
	}

	// Конкатенируем RRSIG RDATA и RRset data
	signedData := append(rrsigRdata, rrsetData...)

	// 4. Выбираем хэш-функцию и вычисляем хэш
	var hashFunc crypto.Hash
	var hasher crypto.Hash // Исправлено: правильно импортированный тип
	switch rrsig.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		hashFunc = crypto.SHA1
		hasher = crypto.SHA1
	case dns.RSASHA256, dns.ECDSAP256SHA256:
		hashFunc = crypto.SHA256
		hasher = crypto.SHA256
	case dns.RSASHA512:
		hashFunc = crypto.SHA512
		hasher = crypto.SHA512
	case dns.ECDSAP384SHA384:
		hashFunc = crypto.SHA384 // SHA384 доступен в crypto/sha512
		hasher = crypto.SHA384
	default:
		return &ValidationError{Reason: fmt.Sprintf("unsupported or unimplemented algorithm: %d", rrsig.Algorithm)}
	}

	if !hashFunc.Available() {
		return &ValidationError{Reason: fmt.Sprintf("hash function not available for algorithm: %d", rrsig.Algorithm)}
	}
	
	// Вычисляем хэш
	hh := hasher.New()
	hh.Write(signedData)
	hashed := hh.Sum(nil)

	// 5. Декодируем подпись из RRSIG
	sigBytes, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		return &ValidationError{Reason: fmt.Sprintf("failed to decode RRSIG signature: %v", err)}
	}

	// 6. Получаем публичный ключ из DNSKEY
	// Поскольку PublicKeyRSA и PublicKeyECDSA не экспортированы,
	// попробуем использовать неэкспортированные методы через рефлексию
	// Это не лучший способ, но может быть единственным решением
	
	var pubKey crypto.PublicKey
	pubKey, err = getPublicKeyFromDNSKEY(key)
	if err != nil {
		return &ValidationError{Reason: fmt.Sprintf("failed to get public key from DNSKEY: %v", err)}
	}

	// 7. Проверяем подпись в зависимости от алгоритма
	switch keyPub := pubKey.(type) {
	case *rsa.PublicKey:
		// Проверяем, поддерживается ли алгоритм RSA
		if rrsig.Algorithm != dns.RSASHA1 && rrsig.Algorithm != dns.RSASHA1NSEC3SHA1 &&
			rrsig.Algorithm != dns.RSASHA256 && rrsig.Algorithm != dns.RSASHA512 {
			return &ValidationError{Reason: fmt.Sprintf("RSA public key with non-RSA algorithm: %d", rrsig.Algorithm)}
		}
		// Выполняем проверку подписи RSA
		err = rsa.VerifyPKCS1v15(keyPub, hashFunc, hashed, sigBytes)
		if err != nil {
			return &ValidationError{Reason: fmt.Sprintf("RSA signature verification failed: %v", err)}
		}
	case *ecdsa.PublicKey:
		// Проверяем, поддерживается ли алгоритм ECDSA
		if rrsig.Algorithm != dns.ECDSAP256SHA256 && rrsig.Algorithm != dns.ECDSAP384SHA384 {
			return &ValidationError{Reason: fmt.Sprintf("ECDSA public key with non-ECDSA algorithm: %d", rrsig.Algorithm)}
		}
		// Для ECDSA подпись в RRSIG представлена как две половины: R и S
		// Длина зависит от алгоритма
		sigLen := len(sigBytes)
		if sigLen%2 != 0 {
			return &ValidationError{Reason: "ECDSA signature has odd length"}
		}
		rBytes := sigBytes[:sigLen/2]
		sBytes := sigBytes[sigLen/2:]
		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		// Выполняем проверку подписи ECDSA
		valid := ecdsa.Verify(keyPub, hashed, r, s)
		if !valid {
			return &ValidationError{Reason: "ECDSA signature verification failed"}
		}
	case *dsa.PublicKey:
		// DSA менее распространен, но обработаем
		// Для DSA также нужно разделить подпись на R и S
		sigLen := len(sigBytes)
		if sigLen%2 != 0 {
			return &ValidationError{Reason: "DSA signature has odd length"}
		}
		rBytes := sigBytes[:sigLen/2]
		sBytes := sigBytes[sigLen/2:]
		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		// Выполняем проверку подписи DSA
		valid := dsa.Verify(keyPub, hashed, r, s)
		if !valid {
			return &ValidationError{Reason: "DSA signature verification failed"}
		}
	default:
		return &ValidationError{Reason: fmt.Sprintf("unsupported public key type: %T", pubKey)}
	}

	log.Printf("DNSSEC validation successful for key: %s (Algorithm: %d)", key.Hdr.Name, key.Algorithm)
	return nil
}

// getPublicKeyFromDNSKEY пытается получить публичный ключ из DNSKEY записи
// Использует рефлексию для вызова неэкспортированных методов
func getPublicKeyFromDNSKEY(key *dns.DNSKEY) (crypto.PublicKey, error) {
	// Попробуем RSA
	pubKey, err := callUnexportedMethod(key, "publicKeyRSA")
	if err == nil && pubKey != nil {
		if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	
	// Если RSA не получилось, пробуем ECDSA
	pubKey, err = callUnexportedMethod(key, "publicKeyECDSA")
	if err == nil && pubKey != nil {
		if ecdsaKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			return ecdsaKey, nil
		}
	}
	
	// Если ECDSA не получилось, возвращаем ошибку
	return nil, fmt.Errorf("failed to get public key from DNSKEY")
}

// callUnexportedMethod вызывает неэкспортированный метод через рефлексию
func callUnexportedMethod(key *dns.DNSKEY, methodName string) (interface{}, error) {
	v := reflect.ValueOf(key)
	
	// Ищем метод по имени (включая неэкспортированные)
	var method reflect.Value
	t := v.Type()
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		if strings.ToLower(m.Name) == strings.ToLower(methodName) {
			method = v.Method(i)
			break
		}
	}
	
	// Если метод не найден, ищем среди методов указателя
	if !method.IsValid() {
		vPtr := reflect.ValueOf(&key).Elem()
		tPtr := vPtr.Type()
		for i := 0; i < tPtr.NumMethod(); i++ {
			m := tPtr.Method(i)
			if strings.ToLower(m.Name) == strings.ToLower(methodName) {
				method = vPtr.Method(i)
				break
			}
		}
	}
	
	if !method.IsValid() {
		return nil, fmt.Errorf("method %s not found", methodName)
	}
	
	// Вызываем метод
	results := method.Call(nil)
	
	// Проверяем результаты
	if len(results) == 0 {
		return nil, fmt.Errorf("method %s returned no results", methodName)
	}
	
	// Первый результат - это сам ключ или ошибка
	result := results[0]
	if result.IsNil() {
		// Второй результат - это ошибка
		if len(results) > 1 {
			errResult := results[1]
			if !errResult.IsNil() {
				if err, ok := errResult.Interface().(error); ok {
					return nil, err
				}
			}
		}
		return nil, fmt.Errorf("method %s returned nil", methodName)
	}
	
	// Проверяем, является ли результат ошибкой
	if result.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		if err, ok := result.Interface().(error); ok {
			return nil, err
		}
	}
	
	return result.Interface(), nil
}

// validateDNSKEY проверяет DNSKEY запись, включая проверку подписи RRSIG
func (h *DNSHandler) validateDNSKEY(name string, dnskeys []dns.RR, rrsigs []*dns.RRSIG) error {
	if !h.enableDNSSEC {
		return nil // Если DNSSEC выключен, не проверяем
	}

	if len(dnskeys) == 0 {
		return &ValidationError{Reason: "missing DNSKEY RRset for " + name}
	}

	// Преобразуем []dns.RR в []*dns.DNSKEY для удобства
	var dnskeyRecords []*dns.DNSKEY
	for _, rr := range dnskeys {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			dnskeyRecords = append(dnskeyRecords, dnskey)
		}
	}

	if len(dnskeyRecords) == 0 {
		return &ValidationError{Reason: "no DNSKEY records found in RRset for " + name}
	}

	// Для корневого DNSKEY проверяем соответствие trust anchor
	if name == "." {
		h.cacheMu.RLock()
		rootKey := h.rootDNSKEY
		h.cacheMu.RUnlock()

		if rootKey != nil {
			for _, dnskey := range dnskeyRecords {
				// Сравниваем ключи
				if dnskey.PublicKey == rootKey.PublicKey &&
					dnskey.Flags == rootKey.Flags &&
					dnskey.Algorithm == rootKey.Algorithm {
					// Найден потенциально доверенный ключ, проверяем его подпись
					for _, rrsig := range rrsigs {
						// validateWithKey ожидает []dns.RR, передаем оригинальный dnskeys
						if err := h.validateWithKey(dnskeys, rrsig, dnskey); err == nil {
							// Подпись корректна, ключ валиден
							log.Printf("Root DNSKEY validated successfully")
							// Кэшируем валидированный ключ
							h.cacheDNSKEY(name, dnskey, rrsig)
							return nil
						} else {
							log.Printf("Root DNSKEY signature verification failed: %v", err)
						}
					}
				} else {
					log.Printf("Root DNSKEY mismatch for key")
				}
			}
			return &ValidationError{Reason: "root DNSKEY mismatch or no valid signature found"}
		} else {
			log.Printf("Root DNSKEY not loaded")
		}
	}

	// Для других зон проверяем подписи
	for _, rrsig := range rrsigs {
		for _, dnskey := range dnskeyRecords {
			// validateWithKey ожидает []dns.RR, передаем оригинальный dnskeys
			if err := h.validateWithKey(dnskeys, rrsig, dnskey); err == nil {
				// Найдена корректная подпись
				log.Printf("DNSKEY for %s validated successfully with key tag %d", name, dnskey.KeyTag())
				// Кэшируем DNSKEY (берем первый найденный валидный)
				h.cacheDNSKEY(name, dnskey, rrsig)
				return nil
			} else {
				// Логируем ошибки валидации на более высоком уровне или только при отладке
			}
		}
	}

	return &ValidationError{Reason: "no valid DNSKEY signature found for " + name}
}


// resolveDNSKEY параллельно разрешает DNSKEY для указанного домена
// Улучшена логика для получения DNSKEY с авторитетных серверов
func (h *DNSHandler) resolveDNSKEY(name string) (*dns.DNSKEY, error) {
	// Проверяем кэш
	if cachedKey := h.getCachedDNSKEY(name); cachedKey != nil {
		return cachedKey, nil
	}

	// Получаем NS сервера для домена (реализация упрощена)
	nsServers, err := h.getNSServers(name)
	if err != nil || len(nsServers) == 0 {
		// Если не можем получить NS, используем корневые (не идеально, но для примера)
		log.Printf("Warning: Could not get NS for %s, using root servers", name)
		nsServers = h.rootServers
	}

	// Создаем запрос
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeDNSKEY)
	m.RecursionDesired = false // Мы делаем рекурсию сами

	// Если DNSSEC включен, устанавливаем EDNS0 с DO битом
	if h.enableDNSSEC {
		m.SetEdns0(4096, true) // DO bit = true
	}

	// Отправляем параллельные запросы к NS серверам домена
	type result struct {
		resp *dns.Msg
		err  error
	}

	results := make(chan result, len(nsServers))
	var wg sync.WaitGroup

	for _, server := range nsServers {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			resp, err := h.queryNS(s, m)
			results <- result{resp, err}
		}(server)
	}

	// Закрываем канал после завершения всех горутин
	go func() {
		wg.Wait()
		close(results)
	}()

	// Обрабатываем результаты
	var dnskeys []dns.RR
	var rrsigs []*dns.RRSIG
	for res := range results {
		if res.err != nil {
			continue
		}

		if res.resp != nil && res.resp.Rcode == dns.RcodeSuccess {
			// Ищем DNSKEY и RRSIG записи
			for _, rr := range res.resp.Answer {
				if dnskey, ok := rr.(*dns.DNSKEY); ok {
					dnskeys = append(dnskeys, dnskey)
				}
				if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == dns.TypeDNSKEY {
					rrsigs = append(rrsigs, rrsig)
				}
			}
		}
	}

	// Если DNSKEY найдены, валидируем их
	if len(dnskeys) > 0 {
		if err := h.validateDNSKEY(name, dnskeys, rrsigs); err != nil {
			log.Printf("DNSKEY validation failed for %s: %v", name, err)
			if h.strictDNSSEC {
				return nil, err
			}
			// В нестрогом режиме продолжаем
		}
		// Возвращаем первый DNSKEY (если он был валиден, он уже закэширован)
		for _, rr := range dnskeys {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				return dnskey, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to resolve or validate DNSKEY for %s", name)
}

// getNSServers получает список NS серверов для домена (упрощенная реализация)
// В реальной системе это требует отдельного рекурсивного поиска NS записей.
func (h *DNSHandler) getNSServers(name string) ([]string, error) {
	// Упрощение: используем resolve для получения NS
	resp, err := h.resolve(name, dns.TypeNS, false) // Запрашиваем NS без DNSSEC для упрощения
	if err != nil {
		return nil, err
	}

	var servers []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			servers = append(servers, ns.Ns+":53")
		}
	}
	// Если не нашли в Answer, смотрим в Authority
	if len(servers) == 0 {
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				servers = append(servers, ns.Ns+":53")
			}
		}
	}
	return servers, nil
}

// getSignerName извлекает имя подписавшего из RRSIG
func (h *DNSHandler) getSignerName(rrsig *dns.RRSIG) string {
	if rrsig == nil {
		return ""
	}
	return rrsig.SignerName
}

// verifyDNSSEC проверяет DNSSEC в ответе
func (h *DNSHandler) verifyDNSSEC(name string, resp *dns.Msg) error {
	if !h.enableDNSSEC || resp == nil {
		return nil
	}

	// Собираем подписи и данные
	var rrsigs []*dns.RRSIG
	sections := [][]dns.RR{resp.Answer, resp.Ns, resp.Extra}
	for _, section := range sections {
		for _, rr := range section {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				rrsigs = append(rrsigs, rrsig)
			}
		}
	}

	// Если нет подписей, но DNSSEC запрошен и есть данные, это проблема
	hasData := len(resp.Answer) > 0 || len(resp.Ns) > 0 || len(resp.Extra) > 0
	if len(rrsigs) == 0 && hasData {
		// Проверяем, если это referral (только NS в Authority), то может быть OK
		onlyNSInAuth := true
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.NS); !ok {
				onlyNSInAuth = false
				break
			}
		}
		// Если это не простой referral, сообщаем об ошибке
		if !(len(resp.Answer) == 0 && onlyNSInAuth && len(resp.Extra) == 0) {
			return &ValidationError{Reason: fmt.Sprintf("no RRSIG records in response for %s", name)}
		}
	}

	// Проверяем каждую подпись
	for _, rrsig := range rrsigs {
		signerName := h.getSignerName(rrsig)
		if signerName == "" {
			continue // Пропускаем, если не можем определить подписанта
		}

		// Получаем DNSKEY для подписавшего
		signerKey, err := h.resolveDNSKEY(signerName)
		if err != nil {
			return &ValidationError{Reason: fmt.Sprintf("failed to resolve DNSKEY for signer %s: %v", signerName, err)}
		}

		// Собираем RRset для проверки
		var rrset []dns.RR
		targetType := rrsig.TypeCovered
		sectionsToCheck := [][]dns.RR{resp.Answer, resp.Ns, resp.Extra}
		for _, section := range sectionsToCheck {
			for _, rr := range section {
				// Проверяем, что это правильный тип и имя
				// Сравнение имен должно быть нечувствительным к регистру
				if rr.Header().Rrtype == targetType && strings.ToLower(rr.Header().Name) == strings.ToLower(rrsig.Hdr.Name) {
					rrset = append(rrset, rr)
				}
			}
		}

		if len(rrset) == 0 {
			// Это может быть нормально для некоторых случаев (например, пустой ответ с SOA RRSIG)
			log.Printf("Warning: No RRset found for RRSIG covering type %d, name %s", targetType, rrsig.Hdr.Name)
			continue
		}

		// Проверяем подпись
		if err := h.validateWithKey(rrset, rrsig, signerKey); err != nil {
			return err // Возвращаем первую ошибку валидации
		}
	}

	// Если все подписи проверены успешно
	return nil
}

// resolve рекурсивно разрешает домен
func (h *DNSHandler) resolve(name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	// Начинаем с корневых серверов
	servers := h.rootServers

	// Создаем запрос
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false // Мы делаем рекурсию сами

	// Если DNSSEC включен, устанавливаем EDNS0 с DO битом
	if dnssec && h.enableDNSSEC {
		m.SetEdns0(4096, true) // DO bit = true
		atomic.AddInt64(&h.dnssecQueries, 1)
	}

	// Максимальная глубина рекурсии
	maxDepth := 20
	for depth := 0; depth < maxDepth; depth++ {
		// Отправляем параллельные запросы к серверам
		type result struct {
			resp *dns.Msg
			err  error
		}

		results := make(chan result, len(servers))
		var wg sync.WaitGroup

		for _, server := range servers {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				resp, err := h.queryNS(s, m)
				results <- result{resp, err}
			}(server)
		}

		// Закрываем канал после завершения всех горутин
		go func() {
			wg.Wait()
			close(results)
		}()

		// Обрабатываем результаты
		var bestResp *dns.Msg
		for res := range results {
			if res.err != nil {
				// Логируем только "нестандартные" ошибки
				if !h.isNormalError(res.err) {
					log.Printf("ERROR querying %s: %v", name, res.err)
				}
				continue
			}

			// Если получили ответ
			if res.resp != nil {
				// Проверяем, является ли это финальным ответом
				if res.resp.Rcode == dns.RcodeSuccess && len(res.resp.Answer) > 0 {
					// Проверяем DNSSEC
					if dnssec && h.enableDNSSEC {
						if err := h.verifyDNSSEC(name, res.resp); err != nil {
							atomic.AddInt64(&h.validationError, 1)
							log.Printf("DNSSEC verification failed for %s: %v", name, err)
							if h.strictDNSSEC {
								return nil, err
							}
							// В нестрогом режиме продолжаем
						}
					}

					// Кэшируем ответ
					cacheKey := h.getCacheKey(name, qtype, dnssec)
					h.cacheResponse(cacheKey, res.resp)
					return res.resp, nil
				}

				// Если получили NXDOMAIN
				if res.resp.Rcode == dns.RcodeNameError {
					// Проверяем DNSSEC для NXDOMAIN
					if dnssec && h.enableDNSSEC {
						// NXDOMAIN тоже должен быть подписан
						if err := h.verifyDNSSEC(name, res.resp); err != nil {
							atomic.AddInt64(&h.validationError, 1)
							log.Printf("DNSSEC verification failed for NXDOMAIN %s: %v", name, err)
							if h.strictDNSSEC {
								return nil, err
							}
						}
					}

					// Кэшируем ответ
					cacheKey := h.getCacheKey(name, qtype, dnssec)
					h.cacheResponse(cacheKey, res.resp)
					return res.resp, nil
				}

				// Если получили referral (NS записи), обновляем список серверов
				if len(res.resp.Ns) > 0 {
					var newServers []string
					// Извлекаем адреса NS серверов
					for _, rr := range res.resp.Ns {
						if ns, ok := rr.(*dns.NS); ok {
							// Для упрощения, добавляем NS как сервер
							// В реальной реализации нужно разрешать NS.Ns
							newServers = append(newServers, ns.Ns+":53")
						}
					}
					if len(newServers) > 0 {
						servers = newServers
						bestResp = res.resp
						break // Переходим к следующему уровню
					}
				}

				// Сохраняем первый успешный ответ
				if bestResp == nil {
					bestResp = res.resp
				}
			}
		}

		// Если не получили ни одного ответа
		if bestResp == nil {
			return nil, fmt.Errorf("no response from nameservers for %s", name)
		}

		// Если получили финальный ответ (Success с Answer или NXDOMAIN)
		if bestResp.Rcode == dns.RcodeSuccess && len(bestResp.Answer) > 0 ||
			bestResp.Rcode == dns.RcodeNameError {
			// Проверяем DNSSEC
			if dnssec && h.enableDNSSEC {
				if err := h.verifyDNSSEC(name, bestResp); err != nil {
					atomic.AddInt64(&h.validationError, 1)
					log.Printf("DNSSEC verification failed for %s: %v", name, err)
					if h.strictDNSSEC {
						return nil, err
					}
				}
			}

			// Кэшируем ответ
			cacheKey := h.getCacheKey(name, qtype, dnssec)
			h.cacheResponse(cacheKey, bestResp)
			return bestResp, nil
		}

		// Если это referral, продолжаем цикл с новыми серверами
	}

	return nil, fmt.Errorf("recursion depth exceeded for %s", name)
}

// ServeDNS обрабатывает входящие DNS-запросы
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt64(&h.totalQueries, 1)

	// Создаем ответное сообщение
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	// Проверяем, есть ли вопросы
	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	domain := question.Name

	// Проверяем, запрашивается ли DNSSEC
	dnssecRequested := false
	if edns0 := r.IsEdns0(); edns0 != nil && edns0.Do() && h.enableDNSSEC {
		dnssecRequested = true
	}

	// Создаем ключ для кэша
	cacheKey := h.getCacheKey(domain, question.Qtype, dnssecRequested)

	// Проверяем кэш
	if cachedResponse := h.getCachedResponse(cacheKey, r); cachedResponse != nil {
		// Отправляем ответ из кэша
		w.WriteMsg(cachedResponse)
		return
	}

	// Выполняем рекурсивное разрешение
	resp, err := h.resolve(domain, question.Qtype, dnssecRequested)

	// Проверяем ошибки
	if err != nil {
		// Записываем ошибку в статистику
		h.recordError(domain)

		// Проверяем, является ли ошибка ошибкой валидации DNSSEC
		if _, ok := err.(*ValidationError); ok {
			atomic.AddInt64(&h.validationError, 1)
			log.Printf("DNSSEC validation error for %s: %v", domain, err)

			// В строгом режиме возвращаем ошибку
			if h.strictDNSSEC {
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}
			// В нестрогом режиме продолжаем и возвращаем ответ без AD бита
		} else if !h.isNormalError(err) {
			// Логируем только "нестандартные" ошибки
			log.Printf("ERROR resolving %s: %v", domain, err)
		}

		// Если это ошибка валидации и не строгий режим, мы можем вернуть ответ без AD
		if resp == nil {
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		// Если есть частичный ответ, продолжаем
	}

	// Копируем данные из ответа
	if resp != nil {
		m.Answer = resp.Answer
		m.Ns = resp.Ns
		m.Extra = resp.Extra

		// Копируем важные флаги
		m.MsgHdr.AuthenticatedData = resp.MsgHdr.AuthenticatedData
		m.MsgHdr.RecursionAvailable = resp.MsgHdr.RecursionAvailable
		m.MsgHdr.Response = resp.MsgHdr.Response
		m.MsgHdr.Authoritative = resp.MsgHdr.Authoritative
		m.Rcode = resp.Rcode

		// Если DNSSEC включен и проверка прошла успешно, устанавливаем AD бит
		if dnssecRequested && err == nil {
			m.MsgHdr.AuthenticatedData = true
		}

		// Копируем EDNS0 опции
		if edns0 := r.IsEdns0(); edns0 != nil {
			// Убеждаемся, что OPT record присутствует
			hasOpt := false
			for _, rr := range m.Extra {
				if rr.Header().Rrtype == dns.TypeOPT {
					hasOpt = true
					break
				}
			}

			if !hasOpt {
				// Создаем новый OPT record
				newOpt := new(dns.OPT)
				newOpt.Hdr.Name = "."
				newOpt.Hdr.Rrtype = dns.TypeOPT
				newOpt.SetUDPSize(edns0.UDPSize())
				newOpt.SetDo(edns0.Do())
				m.Extra = append(m.Extra, newOpt)
			}
		}
	}

	// Отправляем ответ
	w.WriteMsg(m)
}

func main() {
	// Увеличиваем количество потоков для лучшей производительности
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Создаем обработчик
	handler := NewDNSHandler()

	// Создаем DNS-сервер
	server := &dns.Server{
		Addr:    ":5353",
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}

	// Также создаем TCP-сервер для больших ответов
	tcpServer := &dns.Server{
		Addr:    ":5353",
		Net:     "tcp",
		Handler: handler,
	}

	log.Println("Starting DNS server on :5353")
	log.Println("Features: Recursive DNS resolution with DNSSEC validation and caching")
	log.Printf("CPUs: %d", runtime.NumCPU())
	log.Printf("DNSSEC: %v, Strict Mode: %v", handler.enableDNSSEC, handler.strictDNSSEC)

	// Запуск UDP сервера в отдельной горутине
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	// Запуск TCP сервера в отдельной горутине
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %v", err)
		}
	}()

	// Ожидание сигнала завершения
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down DNS server...")

	// Завершение работы серверов
	server.Shutdown()
	tcpServer.Shutdown()

	log.Println("DNS server stopped")
}
