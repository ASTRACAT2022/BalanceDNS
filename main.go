package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
	goresolver "github.com/peterzen/goresolver"
)

// CacheEntry представляет запись в кэше
type CacheEntry struct {
	Msg      *dns.Msg
	ExpireAt int64 // Unix timestamp для быстрой работы
	DNSSECValidated bool // Флаг успешной DNSSEC валидации
	DNSSECFailure   bool // Флаг неудачной DNSSEC валидации
}

// ErrorStats статистика ошибок по доменам
type ErrorStats struct {
	errors map[string]int64
	mutex  sync.RWMutex
}

// DNSHandler обрабатывает DNS-запросы
type DNSHandler struct {
	resolver *resolver.Resolver
	dnssecResolver *goresolver.Resolver // DNSSEC резолвер

	// Кэш с быстрым доступом
	cache    sync.Map // map[string]*CacheEntry
	cacheTTL int64    // в секундах

	// Статистика ошибок
	errorStats *ErrorStats

	// Метрики
	totalQueries  int64
	cachedQueries int64
	dnssecValidatedQueries int64 // Счетчик успешно провалидированных DNSSEC запросов
	dnssecFailedQueries    int64 // Счетчик неудачных DNSSEC проверок

	// Для расчета QPS
	queryCountLast int64
	lastMetricsAt  time.Time
	qps            float64
	qpsMutex       sync.RWMutex

	// Время запуска сервера
	startTime time.Time
	
	// Pool для переиспользуемых объектов
	msgPool sync.Pool
}

// NewDNSHandler создает новый обработчик DNS-запросов
func NewDNSHandler() *DNSHandler {
	// Создаем временный resolv.conf с публичными DNS серверами
	dnsConfig := `nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9`
	
	// Записываем во временный файл
	tmpFile, err := os.CreateTemp("", "dnssec-resolv-*.conf")
	if err != nil {
		log.Printf("Warning: Failed to create temp resolv.conf: %v. DNSSEC validation will be disabled.", err)
		return &DNSHandler{
			resolver:      resolver.NewResolver(),
			dnssecResolver: nil,
			cacheTTL:      300,
			errorStats: &ErrorStats{
				errors: make(map[string]int64),
			},
			lastMetricsAt: time.Now(),
			startTime:     time.Now(),
			msgPool: sync.Pool{
				New: func() interface{} {
					return new(dns.Msg)
				},
			},
		}
	}
	
	// Записываем конфигурацию
	if _, err := tmpFile.WriteString(dnsConfig); err != nil {
		log.Printf("Warning: Failed to write to temp resolv.conf: %v", err)
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return &DNSHandler{
			resolver:      resolver.NewResolver(),
			dnssecResolver: nil,
			cacheTTL:      300,
			errorStats: &ErrorStats{
				errors: make(map[string]int64),
			},
			lastMetricsAt: time.Now(),
			startTime:     time.Now(),
			msgPool: sync.Pool{
				New: func() interface{} {
					return new(dns.Msg)
				},
			},
		}
	}
	
	tmpFile.Close()
	
	// Создаем DNSSEC резолвер с временным файлом
	dnssecResolver, err := goresolver.NewResolver(tmpFile.Name())
	if err != nil {
		log.Printf("Warning: Failed to create DNSSEC resolver: %v. DNSSEC validation will be disabled.", err)
		os.Remove(tmpFile.Name())
		dnssecResolver = nil
	}
	
	handler := &DNSHandler{
		resolver:      resolver.NewResolver(),
		dnssecResolver: dnssecResolver,
		cacheTTL:      300, // 5 минут по умолчанию
		errorStats: &ErrorStats{
			errors: make(map[string]int64),
		},
		lastMetricsAt: time.Now(),
		startTime:     time.Now(),
		msgPool: sync.Pool{
			New: func() interface{} {
				return new(dns.Msg)
			},
		},
	}

	// Настройка резолвера
	resolver.Query = func(s string) {
		// Минимальное логирование upstream запросов
	}

	// Запускаем очистку кэша в отдельной горутине
	go handler.cleanupCache()

	// Запускаем вывод метрик
	go handler.printMetrics()

	// Запускаем вывод сводки ошибок
	go handler.printErrorSummary()

	// Запускаем обновление QPS
	go handler.updateQPS()

	log.Printf("DNSSEC resolver initialized with temp config: %s", tmpFile.Name())
	
	return handler
}

// cleanupCache периодически очищает истекшие записи из кэша
func (h *DNSHandler) cleanupCache() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		now := time.Now().Unix()
		removed := 0

		h.cache.Range(func(key, value interface{}) bool {
			entry := value.(*CacheEntry)
			if now > entry.ExpireAt {
				h.cache.Delete(key)
				removed++
			}
			return true
		})

		if removed > 0 {
			log.Printf("Cache cleanup: removed %d expired entries", removed)
		}
	}
}

// updateQPS обновляет значение QPS
func (h *DNSHandler) updateQPS() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		now := time.Now()
		total := atomic.LoadInt64(&h.totalQueries)
		lastCount := atomic.LoadInt64(&h.queryCountLast)

		// Вычисляем QPS за последнюю секунду
		var qps float64
		if now.Sub(h.lastMetricsAt).Seconds() > 0 {
			qps = float64(total-lastCount) / now.Sub(h.lastMetricsAt).Seconds()
		} else {
			qps = 0
		}

		h.qpsMutex.Lock()
		h.qps = qps
		h.queryCountLast = total
		h.lastMetricsAt = now
		h.qpsMutex.Unlock()
	}
}

// getQPS возвращает текущее значение QPS
func (h *DNSHandler) getQPS() float64 {
	h.qpsMutex.RLock()
	defer h.qpsMutex.RUnlock()
	return h.qps
}

// printMetrics выводит метрики работы сервера
func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		total := atomic.LoadInt64(&h.totalQueries)
		cached := atomic.LoadInt64(&h.cachedQueries)
		dnssecValidated := atomic.LoadInt64(&h.dnssecValidatedQueries)
		dnssecFailed := atomic.LoadInt64(&h.dnssecFailedQueries)
		uptime := time.Since(h.startTime).Truncate(time.Second)

		cacheHitRate := float64(0)
		if total > 0 {
			cacheHitRate = float64(cached) / float64(total) * 100
		}

		dnssecSuccessRate := float64(0)
		totalDNSSECQueries := dnssecValidated + dnssecFailed
		if totalDNSSECQueries > 0 {
			dnssecSuccessRate = float64(dnssecValidated) / float64(totalDNSSECQueries) * 100
		}

		qps := h.getQPS()
		goroutines := runtime.NumGoroutine()

		log.Printf("=== SERVER STATS ===")
		log.Printf("Uptime:           %v", uptime)
		log.Printf("Total Queries:    %d", total)
		log.Printf("Cached Hits:      %d (%.2f%%)", cached, cacheHitRate)
		log.Printf("DNSSEC Validated: %d", dnssecValidated)
		log.Printf("DNSSEC Failed:    %d", dnssecFailed)
		log.Printf("DNSSEC Success:   %.2f%%", dnssecSuccessRate)
		log.Printf("Current QPS:      %.2f", qps)
		log.Printf("Goroutines:       %d", goroutines)
		log.Printf("====================")
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
		} else {
			log.Printf("ERROR SUMMARY - No errors recorded in the last period.")
		}
		h.errorStats.mutex.Unlock()
	}
}

// getCacheKey создает ключ для кэширования
func (h *DNSHandler) getCacheKey(name string, qtype uint16, dnssecRequested bool) string {
	dnssecFlag := "0"
	if dnssecRequested {
		dnssecFlag = "1"
	}
	return name + "|" + fmt.Sprintf("%d", qtype) + "|" + dnssecFlag
}

// getCachedResponse пытается получить ответ из кэша
func (h *DNSHandler) getCachedResponse(key string, request *dns.Msg) *dns.Msg {
	value, exists := h.cache.Load(key)
	if !exists {
		return nil
	}

	entry := value.(*CacheEntry)
	now := time.Now().Unix()

	// Проверяем, не истекло ли время жизни
	if now > entry.ExpireAt {
		h.cache.Delete(key)
		return nil
	}

	// Если была DNSSEC ошибка, возвращаем SERVFAIL
	if entry.DNSSECFailure {
		response := h.msgPool.Get().(*dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		response.MsgHdr.AuthenticatedData = false
		atomic.AddInt64(&h.dnssecFailedQueries, 1)
		return response
	}

	// Получаем сообщение из пула
	cachedMsg := h.msgPool.Get().(*dns.Msg)
	*cachedMsg = *entry.Msg.Copy()

	// Сохраняем оригинальный ID запроса
	cachedMsg.Id = request.Id

	// Копируем EDNS0 опции из оригинального запроса
	if edns0 := request.IsEdns0(); edns0 != nil {
		// Проверяем, есть ли уже OPT record
		hasOpt := false
		for _, rr := range cachedMsg.Extra {
			if rr.Header().Rrtype == dns.TypeOPT {
				// Обновляем существующий OPT record
				opt := rr.(*dns.OPT)
				opt.SetUDPSize(edns0.UDPSize())
				opt.SetDo(edns0.Do())
				hasOpt = true
				break
			}
		}

		// Если нет OPT record, создаем новый
		if !hasOpt {
			newOpt := new(dns.OPT)
			newOpt.Hdr.Name = "."
			newOpt.Hdr.Rrtype = dns.TypeOPT
			newOpt.SetUDPSize(edns0.UDPSize())
			newOpt.SetDo(edns0.Do())
			cachedMsg.Extra = append(cachedMsg.Extra, newOpt)
		}
	}

	// Обновляем TTL в записях
	timeLeft := entry.ExpireAt - now
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

	// Устанавливаем флаг AuthenticatedData если была успешная валидация
	if entry.DNSSECValidated {
		cachedMsg.MsgHdr.AuthenticatedData = true
	}

	atomic.AddInt64(&h.cachedQueries, 1)
	return cachedMsg
}

// returnMsgToPool возвращает сообщение в пул
func (h *DNSHandler) returnMsgToPool(msg *dns.Msg) {
	if msg != nil {
		msg.Id = 0
		msg.Response = false
		msg.Opcode = 0
		msg.Authoritative = false
		msg.Truncated = false
		msg.RecursionDesired = false
		msg.RecursionAvailable = false
		msg.Zero = false
		msg.AuthenticatedData = false
		msg.CheckingDisabled = false
		msg.Rcode = 0
		msg.Question = nil
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		h.msgPool.Put(msg)
	}
}

// cacheResponse сохраняет ответ в кэш
func (h *DNSHandler) cacheResponse(key string, msg *dns.Msg, dnssecValidated bool, dnssecFailure bool) {
	// Определяем минимальный TTL
	minTTL := h.cacheTTL

	// Для NXDOMAIN устанавливаем меньший TTL (например, 30 секунд)
	if msg.Rcode == dns.RcodeNameError {
		minTTL = 30 // NXDOMAIN кэшируем на 30 секунд
	} else if msg.Rcode == dns.RcodeServerFailure && dnssecFailure {
		minTTL = 30 // DNSSEC ошибки кэшируем на 30 секунд
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

	// Для DNSSEC ошибок используем фиксированный TTL
	if dnssecFailure {
		minTTL = 30
	}

	// Создаем копию сообщения для кэширования (без ID и OPT)
	cachedMsg := h.msgPool.Get().(*dns.Msg)
	*cachedMsg = *msg.Copy()

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
	h.cache.Store(key, &CacheEntry{
		Msg:      cachedMsg,
		ExpireAt: expireAt,
		DNSSECValidated: dnssecValidated,
		DNSSECFailure: dnssecFailure,
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
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "Refused") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout")
}

// performDNSSECQuery выполняет DNSSEC валидацию с правильной обработкой ошибок
func (h *DNSHandler) performDNSSECQuery(domain string, qtype uint16) (*dns.Msg, error) {
	// Проверяем, доступен ли DNSSEC резолвер
	if h.dnssecResolver == nil {
		return nil, fmt.Errorf("DNSSEC resolver is not available")
	}
	
	// Создаем DNS сообщение для результата из пула
	resultMsg := h.msgPool.Get().(*dns.Msg)
	resultMsg.SetQuestion(domain, qtype)
	
	// Пытаемся выполнить строгую DNSSEC валидацию
	rrs, err := h.dnssecResolver.StrictNSQuery(domain, qtype)
	if err != nil {
		// ВАЖНО: Не все домены поддерживают DNSSEC!
		// Если ошибка связана с отсутствием подписей, пробуем обычный запрос
		errorStr := err.Error()
		if strings.Contains(errorStr, "RRSIG") || 
		   strings.Contains(errorStr, "signature") || 
		   strings.Contains(errorStr, "DNSKEY") ||
		   strings.Contains(errorStr, "DS") {
			// Это реальная ошибка DNSSEC валидации
			h.returnMsgToPool(resultMsg)
			return nil, fmt.Errorf("DNSSEC validation error: %v", err)
		} else {
			// Другая ошибка - возвращаем как есть
			h.returnMsgToPool(resultMsg)
			return nil, err
		}
	}
	
	resultMsg.Answer = rrs
	resultMsg.Rcode = dns.RcodeSuccess
	return resultMsg, nil
}

// fallbackQuery выполняет обычный запрос при ошибке DNSSEC
func (h *DNSHandler) fallbackQuery(domain string, qtype uint16) (*dns.Msg, error) {
	upstreamMsg := h.msgPool.Get().(*dns.Msg)
	upstreamMsg.SetQuestion(domain, qtype)
	
	// Выполняем запрос с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := h.resolver.Exchange(ctx, upstreamMsg)
	
	// Возвращаем сообщение в пул
	h.returnMsgToPool(upstreamMsg)
	
	return result.Msg, result.Err
}

// ServeDNS обрабатывает входящие DNS-запросы
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt64(&h.totalQueries, 1)

	// Получаем сообщение из пула
	m := h.msgPool.Get().(*dns.Msg)
	m.SetReply(r)
	m.Compress = true

	// Проверяем, есть ли вопросы
	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		h.returnMsgToPool(m)
		return
	}

	question := r.Question[0]
	domain := question.Name
	qtype := question.Qtype

	// Проверяем, запрашивается ли DNSSEC
	dnssecRequested := false
	if edns0 := r.IsEdns0(); edns0 != nil && edns0.Do() {
		dnssecRequested = true
	}

	// Создаем ключ для кэша
	cacheKey := h.getCacheKey(domain, qtype, dnssecRequested)

	// Проверяем кэш
	if cachedResponse := h.getCachedResponse(cacheKey, r); cachedResponse != nil {
		// Отправляем ответ из кэша
		w.WriteMsg(cachedResponse)
		// Возвращаем сообщения в пул
		h.returnMsgToPool(m)
		h.returnMsgToPool(cachedResponse)
		return
	}

	var resultMsg *dns.Msg
	var dnssecError error
	dnssecValidated := false
	dnssecFailure := false

	// Если запрошен DNSSEC и резолвер доступен, выполняем валидацию
	if dnssecRequested && h.dnssecResolver != nil {
		resultMsg, dnssecError = h.performDNSSECQuery(domain, qtype)
		if dnssecError != nil {
			// Записываем ошибку DNSSEC в статистику
			atomic.AddInt64(&h.dnssecFailedQueries, 1)
			h.recordError(domain)
			dnssecFailure = true
			
			// Логируем ошибку DNSSEC
			log.Printf("DNSSEC validation failed for %s type %s: %v", domain, dns.TypeToString[qtype], dnssecError)
			
			// Попробуем fallback - обычный запрос без DNSSEC
			fallbackMsg, fallbackErr := h.fallbackQuery(domain, qtype)
			if fallbackErr != nil {
				// Если и fallback не работает, сохраняем ошибку в кэш
				errorMsg := h.msgPool.Get().(*dns.Msg)
				errorMsg.SetRcode(r, dns.RcodeServerFailure)
				h.cacheResponse(cacheKey, errorMsg, false, true)
				h.returnMsgToPool(errorMsg)
				
				// Возвращаем SERVFAIL
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				h.returnMsgToPool(m)
				return
			}
			
			// Используем результат fallback запроса
			resultMsg = fallbackMsg
			dnssecFailure = false // Сбрасываем флаг ошибки
		} else {
			// Успешная DNSSEC валидация
			atomic.AddInt64(&h.dnssecValidatedQueries, 1)
			dnssecValidated = true
			
			// Устанавливаем флаг AuthenticatedData
			if resultMsg != nil {
				resultMsg.MsgHdr.AuthenticatedData = true
			}
		}
	} else {
		// Обычный запрос без DNSSEC или если DNSSEC недоступен
		upstreamMsg := h.msgPool.Get().(*dns.Msg)
		upstreamMsg.SetQuestion(domain, qtype)

		// Выполняем запрос с таймаутом
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result := h.resolver.Exchange(ctx, upstreamMsg)
		
		// Возвращаем сообщение в пул
		h.returnMsgToPool(upstreamMsg)

		// Проверяем ошибки
		if result.Err != nil {
			// Записываем ошибку в статистику
			h.recordError(domain)

			// Логируем только "нестандартные" ошибки
			if !h.isNormalError(result.Err) {
				log.Printf("ERROR resolving %s type %s: %v", domain, dns.TypeToString[qtype], result.Err)
			}

			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			h.returnMsgToPool(m)
			if result.Msg != nil {
				h.returnMsgToPool(result.Msg)
			}
			return
		}

		resultMsg = result.Msg
	}

	// Копируем данные из ответа
	if resultMsg != nil {
		m.Answer = resultMsg.Answer
		m.Ns = resultMsg.Ns
		m.Extra = resultMsg.Extra

		// Копируем важные флаги
		m.MsgHdr.AuthenticatedData = resultMsg.MsgHdr.AuthenticatedData || dnssecValidated
		m.MsgHdr.RecursionAvailable = resultMsg.MsgHdr.RecursionAvailable
		m.MsgHdr.Response = resultMsg.MsgHdr.Response
		m.MsgHdr.Authoritative = resultMsg.MsgHdr.Authoritative
		m.Rcode = resultMsg.Rcode

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

		// Сохраняем в кэш
		h.cacheResponse(cacheKey, resultMsg, dnssecValidated, dnssecFailure)
	}

	// Отправляем ответ
	w.WriteMsg(m)
	
	// Возвращаем сообщения в пул
	h.returnMsgToPool(m)
	if resultMsg != nil && resultMsg != m {
		h.returnMsgToPool(resultMsg)
	}
}

func main() {
	// Увеличиваем количество потоков для лучшей производительности
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Создаем обработчик
	handler := NewDNSHandler()

	// Создаем DNS-сервер
	server := &dns.Server{
		Addr:    ":5311", // Оставляем порт 5311
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}

	// Также создаем TCP-сервер для больших ответов
	tcpServer := &dns.Server{
		Addr:    ":5311",
		Net:     "tcp",
		Handler: handler,
	}

	log.Println("Starting DNS server on :5311")
	log.Println("Features: Caching with DNSSEC support + Error statistics + Metrics")
	log.Printf("CPUs: %d", runtime.NumCPU())
	log.Println("Supported record types: ALL (A, AAAA, MX, TXT, NS, CNAME, PTR, SRV, etc.)")
	
	// Проверяем, доступен ли DNSSEC
	if handler.dnssecResolver != nil {
		log.Println("DNSSEC validation: ENABLED (using public DNS servers)")
	} else {
		log.Println("DNSSEC validation: DISABLED (resolver not available)")
	}

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
