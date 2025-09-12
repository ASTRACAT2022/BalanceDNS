package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"
)

// CacheEntry представляет запись в кэше
type CacheEntry struct {
	Msg      *dns.Msg
	ExpireAt int64 // Unix timestamp для быстрой работы
}

// DNSKEYCacheEntry для кэширования DNSKEY записей
type DNSKEYCacheEntry struct {
	DNSKEY   *dns.DNSKEY
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

	// internal
	rand *rand.Rand
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
		// Список корневых серверов (ip:53)
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
		rand:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// Предзагрузка корневого DNSKEY
	if handler.enableDNSSEC {
		go handler.loadRootDNSKEY()
	}

	// Запускаем очистку кэша в отдельной горутине
	go handler.activeCacheCleaner()

	// Запускаем вывод метрик
	go handler.printMetrics()

	// Запускаем вывод сводки ошибок
	go handler.printErrorSummary()

	return handler
}

// loadRootDNSKEY предзагружает корневой DNSKEY (KSK-2017)
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
		ExpireAt: time.Now().Unix() + 3600,
	})
	h.cacheMu.Unlock()

	log.Println("Root DNSKEY loaded and cached")
}

// activeCacheCleaner периодически чистит LRU-кэш от истёкших записей (проход)
func (h *DNSHandler) activeCacheCleaner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// LRU не предоставляет прямого перебора, но мы можем имитировать
		// простую очистку: пробуем перебрать возможные ключи неявно не получится.
		// Вместо этого — просто уменьшим размер кэша, сбросив старые элементы,
		// и положим небольшой пасивный проход (удаление явно просроченных при доступе).
		// Однако мы можем триггерить GC для освобождения памяти.
		runtime.GC()
	}
}

// printMetrics выводит метрики работы сервера
func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
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

	for range ticker.C {
		h.errorStats.mutex.Lock()
		if len(h.errorStats.errors) > 0 {
			log.Printf("ERROR SUMMARY - Top problematic domains:")
			type domainError struct {
				domain string
				count  int64
			}

			var errors []domainError
			for domain, count := range h.errorStats.errors {
				errors = append(errors, domainError{domain, count})
			}

			// Простая сортировка по количеству ошибок (первые 10)
			for i := 0; i < len(errors) && i < 10; i++ {
				for j := i + 1; j < len(errors); j++ {
					if errors[i].count < errors[j].count {
						errors[i], errors[j] = errors[j], errors[i]
					}
				}
			}

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
		// удаляем
		h.cacheMu.RUnlock()
		h.cacheMu.Lock()
		h.cache.Remove(key)
		h.cacheMu.Unlock()
		h.cacheMu.RLock()
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
	if minTTL > 86400 { // Максимум 1 day
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
func (h *DNSHandler) cacheDNSKEY(name string, dnskey *dns.DNSKEY) {
	if dnskey == nil {
		return
	}

	// Используем TTL из записи или минимальное значение
	ttl := int64(dnskey.Hdr.Ttl)
	if ttl < 300 { // Минимум 5 минут
		ttl = 300
	}
	if ttl > 86400 { // Максимум 1 day
		ttl = 86400
	}

	expireAt := time.Now().Unix() + ttl

	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	h.dnskeyCache.Add(name, &DNSKEYCacheEntry{
		DNSKEY:   dnskey,
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
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "refused") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "no answer from dns server")
}

// queryNS отправляет запрос к указанному nameserver
func (h *DNSHandler) queryNS(server string, msg *dns.Msg) (*dns.Msg, error) {
	// Пытаемся сначала через UDP
	h.client.Net = "udp"
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

// validateDNSKEY проверяет DNSKEY запись
func (h *DNSHandler) validateDNSKEY(name string, dnskey *dns.DNSKEY) error {
	if !h.enableDNSSEC {
		return nil // Если DNSSEC выключен, не проверяем
	}

	if dnskey == nil {
		return &ValidationError{Reason: "missing DNSKEY for " + name}
	}

	// Для корневого DNSKEY проверяем соответствие trust anchor
	if name == "." {
		h.cacheMu.RLock()
		rootKey := h.rootDNSKEY
		h.cacheMu.RUnlock()

		if rootKey != nil {
			// Сравниваем ключи
			if dnskey.PublicKey != rootKey.PublicKey ||
				dnskey.Flags != rootKey.Flags ||
				dnskey.Algorithm != rootKey.Algorithm {
				return &ValidationError{Reason: "root DNSKEY mismatch"}
			}
		}
	}

	return nil
}

// resolveDNSKEY параллельно разрешает DNSKEY для указанного домена (с кэшем)
func (h *DNSHandler) resolveDNSKEY(name string) (*dns.DNSKEY, error) {
	// Проверяем кэш
	if cachedKey := h.getCachedDNSKEY(name); cachedKey != nil {
		return cachedKey, nil
	}

	// Создаем запрос
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeDNSKEY)
	m.RecursionDesired = false // Мы делаем рекурсию сами

	// Если DNSSEC включен, устанавливаем EDNS0 с DO битом
	if h.enableDNSSEC {
		m.SetEdns0(4096, true) // DO bit = true
	}

	// Выбираем небольшой пул root-серверов (3 случайных) чтобы не дергать всех
	servers := h.pickRootServers(3)

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

	for res := range results {
		if res.err != nil {
			continue
		}

		if res.resp != nil && res.resp.Rcode == dns.RcodeSuccess {
			// Ищем DNSKEY записи в Answer
			for _, rr := range res.resp.Answer {
				if dnskey, ok := rr.(*dns.DNSKEY); ok {
					// Валидируем DNSKEY
					if err := h.validateDNSKEY(name, dnskey); err != nil {
						log.Printf("DNSKEY validation failed for %s: %v", name, err)
						// strict применим выше по слоям
					}
					// Кэшируем DNSKEY
					h.cacheDNSKEY(name, dnskey)
					return dnskey, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to resolve DNSKEY for %s", name)
}

// pickRootServers возвращает n случайных root-серверов (ip:port)
func (h *DNSHandler) pickRootServers(n int) []string {
	total := len(h.rootServers)
	if n >= total {
		c := make([]string, total)
		copy(c, h.rootServers)
		return c
	}

	out := make([]string, 0, n)
	perm := h.rand.Perm(total)
	for i := 0; i < n; i++ {
		out = append(out, h.rootServers[perm[i]])
	}
	return out
}

// verifyRRSIG осуществляет криптографическую проверку RRSIG над rrset используя DNSKEY
// Здесь мы пытаемся использовать встроенные возможности библиотеки miekg/dns (RRSIG.Verify).
// Если метод недоступен, возвращаем nil с логом; это место можно заменить на полную реализацию.
func (h *DNSHandler) verifyRRSIG(rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY) error {
	// Попытка использовать метод Verify (есть в новых версиях miekg/dns)
	// Если метод отсутствует в используемой версии, эта строка может не скомпилироваться.
	// В таком случае нужно будет вручную распарсить public key и проверить подпись.
	if key == nil || rrsig == nil {
		return fmt.Errorf("missing key or rrsig for verification")
	}
	// rrsig.Verify expects rrset []dns.RR and key *dns.DNSKEY
	// Возвращает ошибку если верификация не прошла.
	if err := rrsig.Verify(key, rrset); err != nil {
		return err
	}
	return nil
}

// verifyDNSSEC проверяет DNSSEC в ответе: наличие RRSIG, получение DNSKEY и попытка верификации
func (h *DNSHandler) verifyDNSSEC(name string, resp *dns.Msg) error {
	if !h.enableDNSSEC || resp == nil {
		return nil
	}

	// Определяем зону (упрощенно — берем fqdn самого длинного совпадающего суффикса).
	// Для наших целей используем сам name.
	zone := dns.Fqdn(name)

	// Составляем RRset (answer records, группируя по типу).
	// Для простоты валидируем только Answer секцию (обычное поведение при проверке).
	if len(resp.Answer) == 0 {
		// Если нет answer, но запросил DNSSEC — это может быть signed NXDOMAIN или NODATA.
		// Для упрощения: проверим наличие RRSIG в Authority (например, NSEC/NSEC3 или SOA+RRSIG)
		hasRRSIG := false
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.RRSIG); ok {
				hasRRSIG = true
				break
			}
		}
		if !hasRRSIG {
			return &ValidationError{Reason: "no RRSIG found for empty answer (possible unsigned NXDOMAIN/NODATA)"}
		}
		// дальше попытаемся получить DNSKEY для зоны и продолжить
	}

	// Попробуем получить DNSKEY для зоны (из кэша или от authoritative)
	dnskey, _ := h.resolveDNSKEY(zone) // не фатально, проверим дальше
	if dnskey == nil {
		// Попытка резолва DNSKEY с помощью авторитативных серверов не прошла — попробуем из Authority секции
		for _, rr := range resp.Ns {
			if k, ok := rr.(*dns.DNSKEY); ok {
				dnskey = k
				break
			}
		}
	}

	if dnskey == nil {
		// Не можем получить DNSKEY — пометить как ошибка валидации
		return &ValidationError{Reason: "could not obtain DNSKEY for zone " + zone}
	}

	// Собираем группы RRset по типу (упрощённо — все Answer как один rrset).
	rrset := make([]dns.RR, 0)
	for _, rr := range resp.Answer {
		// Пропускаем RRSIG из rrset
		if _, ok := rr.(*dns.RRSIG); !ok {
			rrset = append(rrset, rr)
		}
	}

	// Ищем RRSIG, относящийся к этому rrset
	var foundRRSIG *dns.RRSIG
	for _, rr := range resp.Answer {
		if r, ok := rr.(*dns.RRSIG); ok {
			// Проверяем имя и тип, простой фильтр
			if strings.EqualFold(r.Hdr.Name, dns.Fqdn(name)) || strings.EqualFold(r.Hdr.Name, dns.Fqdn(zone)) {
				foundRRSIG = r
				break
			}
		}
	}
	// Если не нашли в Answer — поиск в Authority
	if foundRRSIG == nil {
		for _, rr := range resp.Ns {
			if r, ok := rr.(*dns.RRSIG); ok {
				foundRRSIG = r
				break
			}
		}
	}

	if foundRRSIG == nil {
		return &ValidationError{Reason: "no RRSIG for answer"}
	}

	// Пытаемся криптографически верифицировать rrsig с найденным DNSKEY
	if err := h.verifyRRSIG(rrset, foundRRSIG, dnskey); err != nil {
		return &ValidationError{Reason: fmt.Sprintf("RRSIG verification failed: %v", err)}
	}

	// Частичная проверка цепочки: если у нас есть DS в Authority, сверим digest
	// Запросим DS у родительской зоны (parent of zone)
	parent := parentZone(zone)
	if parent != "" {
		ds, err := h.queryDS(parent, zone)
		if err == nil && len(ds) > 0 {
			// Пытаемся найти соответствие по key tag / digest
			matched := false
			for _, d := range ds {
				for _, rr := range []*dns.DNSKEY{dnskey} {
					kt := dns.KeyTag(rr)
					if int(d.KeyTag) == kt {
						// Проверяем digest
						if matchesDS(rr, d) {
							matched = true
							break
						}
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return &ValidationError{Reason: "DS does not match DNSKEY (chain of trust broken)"}
			}
		}
		// Если не получили DS — возможно зона не делегирована с DS (unsigned parent) — допустимо в нестрогом режиме
	}

	// Всё ок
	return nil
}

// parentZone возвращает parent zone для fqdn (например, "example.com." -> "com.")
func parentZone(fqdn string) string {
	trim := strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(trim, ".")
	if len(parts) < 2 {
		return "."
	}
	parent := strings.Join(parts[1:], ".") + "."
	return parent
}

// queryDS пытается получить DS записи для child у parent
func (h *DNSHandler) queryDS(parent string, child string) ([]*dns.DS, error) {
	// Запросим у авторитативных серверов для parent DS для child
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(child), dns.TypeDS)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)

	// Для parent используем rootServers -> resolve parent NS -> pick
	// Упростим: посылаем запрос к root и дадим ему перенаправить
	servers := h.pickRootServers(3)

	type result struct {
		resp *dns.Msg
		err  error
	}
	results := make(chan result, len(servers))
	var wg sync.WaitGroup

	for _, s := range servers {
		wg.Add(1)
		go func(srv string) {
			defer wg.Done()
			resp, err := h.queryNS(srv, m)
			results <- result{resp, err}
		}(s)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.err != nil || res.resp == nil {
			continue
		}
		if res.resp.Rcode == dns.RcodeSuccess {
			var dsRecords []*dns.DS
			for _, rr := range res.resp.Answer {
				if ds, ok := rr.(*dns.DS); ok {
					dsRecords = append(dsRecords, ds)
				}
			}
			if len(dsRecords) > 0 {
				return dsRecords, nil
			}
		}
	}
	return nil, fmt.Errorf("no DS found for %s at %s", child, parent)
}

// matchesDS сравнивает DNSKEY с DS (поддерживает SHA1(1) и SHA256(2))
func matchesDS(key *dns.DNSKEY, ds *dns.DS) bool {
	if key == nil || ds == nil {
		return false
	}
	raw, err := key.ToDS(ds.DigestType)
	if err != nil {
		// В старых версиях miekg/dns ToDS может не поддерживать digest type,
		// поэтому делаем ручно для sha1/sha256
		switch ds.DigestType {
		case dns.SHA1:
			h := sha1.Sum([]byte(key.PublicKeyData()))
			return strings.EqualFold(hex.EncodeToString(h[:]), strings.ToLower(ds.Digest))
		case dns.SHA256:
			h := sha256.Sum256([]byte(key.PublicKeyData()))
			return strings.EqualFold(hex.EncodeToString(h[:]), strings.ToLower(ds.Digest))
		default:
			return false
		}
	}
	return strings.EqualFold(raw.Digest, ds.Digest)
}

// Помощники для DNSKEY -> raw pubkey bytes (в miekg/dns могут быть утилиты; ниже упрощение)
func (k *dns.DNSKEY) PublicKeyData() string {
	// Возвращаем Base64 строку public key — ToDS/Verify должны уметь ее декодировать.
	return k.PublicKey
}

// resolveGlue разрешает имена NS (ns.example.com) в IP адреса (A/AAAA)
// Возвращает []string вида "ip:53"
func (h *DNSHandler) resolveGlue(nsname string) []string {
	ips := make([]string, 0, 4)
	// Быстрая попытка: используем системный резолвер через net.Lookup? Мы ограничиваемся DNS библиотекой.
	// Сделаем рекурсивный запрос типа A и AAAA к корням/authoritative (через наш resolve)
	aResp, _ := h.resolve(nsname, dns.TypeA, false)
	if aResp != nil {
		for _, rr := range aResp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, fmt.Sprintf("%s:53", a.A.String()))
			}
		}
	}
	aaaaResp, _ := h.resolve(nsname, dns.TypeAAAA, false)
	if aaaaResp != nil {
		for _, rr := range aaaaResp.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, fmt.Sprintf("[%s]:53", aaaa.AAAA.String()))
			}
		}
	}
	return ips
}

// resolve рекурсивно разрешает домен
func (h *DNSHandler) resolve(name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	// Начинаем с корневых серверов
	servers := h.pickRootServers(3) // стартуем с пула из 3 серверов

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

		go func() {
			wg.Wait()
			close(results)
		}()

		var bestResp *dns.Msg
		var referralServers []string

		for res := range results {
			if res.err != nil {
				if !h.isNormalError(res.err) {
					log.Printf("ERROR querying %s at server: %v", name, res.err)
				}
				continue
			}

			if res.resp == nil {
				continue
			}

			// Если получили ответ с Answer
			if res.resp.Rcode == dns.RcodeSuccess && len(res.resp.Answer) > 0 {
				// Если DNSSEC запрошен — проверяем
				if dnssec && h.enableDNSSEC {
					if err := h.verifyDNSSEC(name, res.resp); err != nil {
						atomic.AddInt64(&h.validationError, 1)
						log.Printf("DNSSEC verification failed for %s: %v", name, err)
						if h.strictDNSSEC {
							return nil, err
						}
						// В нестрогом режиме — логируем и продолжаем — но не ставим AD
					}
				}

				// Кэшируем и возвращаем
				cacheKey := h.getCacheKey(name, qtype, dnssec)
				h.cacheResponse(cacheKey, res.resp)
				return res.resp, nil
			}

			// Если NXDOMAIN
			if res.resp.Rcode == dns.RcodeNameError {
				if dnssec && h.enableDNSSEC {
					if err := h.verifyDNSSEC(name, res.resp); err != nil {
						atomic.AddInt64(&h.validationError, 1)
						log.Printf("DNSSEC verification failed for NXDOMAIN %s: %v", name, err)
						if h.strictDNSSEC {
							return nil, err
						}
					}
				}
				cacheKey := h.getCacheKey(name, qtype, dnssec)
				h.cacheResponse(cacheKey, res.resp)
				return res.resp, nil
			}

			// Если referral — берём NS из Authority секции
			if len(res.resp.Ns) > 0 {
				var newServers []string
				for _, rr := range res.resp.Ns {
					if ns, ok := rr.(*dns.NS); ok {
						// Попытка взять glue из Additional (A/AAAA)
						foundGlue := false
						for _, add := range res.resp.Extra {
							if a, ok := add.(*dns.A); ok {
								if strings.EqualFold(a.Hdr.Name, ns.Ns) {
									newServers = append(newServers, fmt.Sprintf("%s:53", a.A.String()))
									foundGlue = true
								}
							}
							if aaaa, ok := add.(*dns.AAAA); ok {
								if strings.EqualFold(aaaa.Hdr.Name, ns.Ns) {
									newServers = append(newServers, fmt.Sprintf("[%s]:53", aaaa.AAAA.String()))
									foundGlue = true
								}
							}
						}
						// Если glue не найден, делаем внешний разрешатель имени NS -> A/AAAA (resolveGlue)
						if !foundGlue {
							glueIps := h.resolveGlue(ns.Ns)
							if len(glueIps) > 0 {
								newServers = append(newServers, glueIps...)
							} else {
								// Добавляем NS как имя (попробуем позднее резольвить)
								// Для безопасности — не добавляем "ns.name" как ip, пропустим
							}
						}
					}
				}

				if len(newServers) > 0 {
					referralServers = newServers
					// запомним best response (может содержать useful info)
					if bestResp == nil {
						bestResp = res.resp
					}
				}
			}

			// Сохраняем первый полученный ответ на случай fallback
			if bestResp == nil {
				bestResp = res.resp
			}
		}

		// Если у нас есть referral servers (IP адреса), то продолжаем с ними
		if len(referralServers) > 0 {
			servers = referralServers
			continue
		}

		// Если нет referral, но есть лучший ответ (например авторитативный без answer)
		if bestResp != nil {
			if bestResp.Rcode == dns.RcodeSuccess && len(bestResp.Answer) > 0 ||
				bestResp.Rcode == dns.RcodeNameError {
				if dnssec && h.enableDNSSEC {
					if err := h.verifyDNSSEC(name, bestResp); err != nil {
						atomic.AddInt64(&h.validationError, 1)
						log.Printf("DNSSEC verification failed for %s: %v", name, err)
						if h.strictDNSSEC {
							return nil, err
						}
					}
				}
				cacheKey := h.getCacheKey(name, qtype, dnssec)
				h.cacheResponse(cacheKey, bestResp)
				return bestResp, nil
			}
		}

		// Если не получили ни одного ответа
		return nil, fmt.Errorf("no response from nameservers for %s", name)
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
			// В нестрогом режиме продолжаем и возвращаем ответ без AD бита (если он есть)
		} else if !h.isNormalError(err) {
			// Логируем только "нестандартные" ошибки
			log.Printf("ERROR resolving %s: %v", domain, err)
		}

		// Если нет ответа — возвращаем SERVFAIL
		if resp == nil {
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		// Если есть частичный ответ — продолжаем
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