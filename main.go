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

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

const (
	// Конфигурация кэша
	defaultCacheSize int64 = 1 << 30 // 1GB
	defaultCacheItems int64 = 100000
	defaultCacheTTL         = 5 * time.Minute
	nxdomainCacheTTL        = 30 * time.Second

	// Конфигурация метрик
	metricsInterval     = 30 * time.Second
	errorSummaryInterval = 5 * time.Minute
	// cacheCleanupInterval = 1 * time.Minute // Ristretto сам очищает, но лог полезен

	// Конфигурация сети
	defaultUDPPacketSize = 4096 // Стандартный размер UDP пакета
)

// ErrorStats статистика ошибок по доменам
// Используем атомарные операции для lock-free доступа
type ErrorStats struct {
	// Используем map[string]*int64 для возможности атомарного инкремента
	// Ключ - это домен, значение - указатель на счетчик
	errors sync.Map // map[string]*int64
}

// DNSHandler обрабатывает DNS-запросы
type DNSHandler struct {
	resolver *resolver.Resolver

	// Высокопроизводительный кэш, хранящий сериализованные ответы ([]byte)
	cache *ristretto.Cache

	// Статистика ошибок
	errorStats *ErrorStats

	// Метрики (атомарные для высокой производительности)
	totalQueries  int64
	cachedHits    int64 // Hits из кэша
	cachedMisses  int64 // Misses (запросы в upstream)
	totalErrors   int64 // Общее количество ошибок резолвинга

	// sync.Pool для уменьшения аллокаций
	msgPool    sync.Pool // *dns.Msg
	builderPool sync.Pool // *strings.Builder
}

// NewDNSHandler создает новый обработчик DNS-запросов
func NewDNSHandler() *DNSHandler {
	// Создаем кэш Ristretto
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: defaultCacheItems * 10, // Нужно для точности, обычно в 10 раз больше чем MaxCost
		MaxCost:     defaultCacheSize,       // Максимальный размер кэша в байтах
		BufferItems: 64,                     // Размер буфера для каналов
		Metrics:     true,                   // Включаем метрики для мониторинга
	})
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	handler := &DNSHandler{
		resolver:   resolver.NewResolver(),
		cache:      cache,
		errorStats: &ErrorStats{},
		msgPool: sync.Pool{
			New: func() interface{} {
				return new(dns.Msg)
			},
		},
		builderPool: sync.Pool{
			New: func() interface{} {
				return new(strings.Builder)
			},
		},
	}

	// Настройка резолвера (минимальное логирование)
	resolver.Query = func(s string) {
		// Логирование upstream запросов, если необходимо, но минимальное
	}

	// Запускаем вывод метрик
	go handler.printMetrics()

	// Запускаем вывод сводки ошибок
	go handler.printErrorSummary()

	// Запускаем вывод метрик кэша (по желанию, для отладки)
	// go handler.printCacheMetrics()

	return handler
}

// printMetrics выводит метрики работы сервера
func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		total := atomic.LoadInt64(&h.totalQueries)
		cachedHits := atomic.LoadInt64(&h.cachedHits)
		cachedMisses := atomic.LoadInt64(&h.cachedMisses)
		totalErrors := atomic.LoadInt64(&h.totalErrors)

		cacheHitRate := float64(0)
		if total > 0 {
			cacheHitRate = float64(cachedHits) / float64(total) * 100
		}

		log.Printf("METRICS - Total: %d, Cached Hits: %d, Cache Misses: %d, Errors: %d, Hit Rate: %.2f%%",
			total, cachedHits, cachedMisses, totalErrors, cacheHitRate)
	}
}

// printErrorSummary выводит сводку по ошибкам
func (h *DNSHandler) printErrorSummary() {
	ticker := time.NewTicker(errorSummaryInterval)
	defer ticker.Stop()

	for {
		<-ticker.C

		// Собираем текущие ошибки в локальный слайс для сортировки
		// и освобождаем оригинальный sync.Map
		var errors []struct {
			domain string
			count  int64
		}

		h.errorStats.errors.Range(func(key, value interface{}) bool {
			domain := key.(string)
			// Атомарно загружаем значение счетчика
			countPtr := value.(*int64)
			count := atomic.LoadInt64(countPtr)
			if count > 0 {
				errors = append(errors, struct {
					domain string
					count  int64
				}{domain, count})
				// Удаляем из оригинальной карты после сбора
				h.errorStats.errors.Delete(key)
			}
			return true
		})

		if len(errors) > 0 {
			// Сортировка по количеству ошибок (простая bubble sort для первых 10)
			// Для более сложных сценариев используйте sort.Slice
			for i := 0; i < len(errors) && i < 10; i++ {
				for j := i + 1; j < len(errors); j++ {
					if errors[i].count < errors[j].count {
						errors[i], errors[j] = errors[j], errors[i]
					}
				}
			}

			log.Printf("ERROR SUMMARY - Top problematic domains:")
			for i := 0; i < len(errors) && i < 10; i++ {
				log.Printf("  %s: %d errors", errors[i].domain, errors[i].count)
			}
		}
	}
}

// printCacheMetrics выводит метрики кэша Ristretto (для отладки)
// func (h *DNSHandler) printCacheMetrics() {
// 	ticker := time.NewTicker(cacheCleanupInterval)
// 	defer ticker.Stop()
//
// 	for {
// 		<-ticker.C
// 		// Проверьте документацию ristretto на актуальные методы метрик
// 		// Пример (проверьте имена методов в вашей версии ristretto):
// 		log.Printf("CACHE METRICS - Hits: %d, Misses: %d, Cost Added: %d",
// 			h.cache.Metrics.Hits(), h.cache.Metrics.Misses(), h.cache.Metrics.CostAdded())
// 			// h.cache.Metrics.GetsTotal()) // Этот метод может отсутствовать
// 	}
// }

// getFromPool получает *dns.Msg из пула
func (h *DNSHandler) getFromPool() *dns.Msg {
	return h.msgPool.Get().(*dns.Msg)
}

// putToPool возвращает *dns.Msg в пул
func (h *DNSHandler) putToPool(m *dns.Msg) {
	// Очищаем сообщение перед возвратом в пул
	*m = dns.Msg{} // Это эффективный способ сброса всех полей
	h.msgPool.Put(m)
}

// getCachedResponse пытается получить сериализованный ответ из кэша
func (h *DNSHandler) getCachedResponse(name string, qtype uint16) ([]byte, bool) {
	key := h.buildCacheKey(name, qtype)
	value, found := h.cache.Get(key)
	if !found {
		return nil, false
	}
	// Преобразуем interface{} обратно в []byte
	// Ristretto возвращает копию данных, что безопасно
	if data, ok := value.([]byte); ok {
		return data, true
	}
	return nil, false
}

// cacheResponse сохраняет сериализованный ответ в кэш
func (h *DNSHandler) cacheResponse(name string, qtype uint16, msg *dns.Msg) {
	// Определяем TTL для кэширования
	ttl := defaultCacheTTL
	if msg.Rcode == dns.RcodeNameError {
		ttl = nxdomainCacheTTL
	} else {
		// Ищем минимальный TTL во всех секциях для успешных ответов
		sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
		minTTL := int64(defaultCacheTTL.Seconds())
		foundTTL := false
		for _, section := range sections {
			for _, rr := range section {
				// Пропускаем OPT record при расчете TTL
				if rr.Header().Rrtype != dns.TypeOPT {
					foundTTL = true
					if int64(rr.Header().Ttl) < minTTL && rr.Header().Ttl > 0 {
						minTTL = int64(rr.Header().Ttl)
					}
				}
			}
		}
		if foundTTL {
			ttl = time.Duration(minTTL) * time.Second
		}
	}

	// Сериализуем сообщение
	packed, err := msg.Pack()
	if err != nil {
		log.Printf("ERROR: Failed to pack message for caching: %v", err)
		return // Не кэшируем, если не удалось сериализовать
	}
	// Копируем данные, чтобы изолировать их от внутреннего буфера msg.Pack
	data := append([]byte(nil), packed...)

	// Создаем ключ (теперь это string)
	key := h.buildCacheKey(name, qtype)

	// Сохраняем в кэш. Стоимость - длина данных.
	// Ristretto сам управляет TTL и eviction.
	h.cache.SetWithTTL(key, data, int64(len(data)), ttl)
}

// buildCacheKey создает ключ для кэширования в виде string
func (h *DNSHandler) buildCacheKey(name string, qtype uint16) string {
	// Используем strings.Builder из пула для минимизации аллокаций
	sb := h.builderPool.Get().(*strings.Builder)
	sb.Reset() // Очищаем перед использованием

	sb.WriteString(name)
	sb.WriteString("|")
	// Используем AppendUint для эффективного добавления числа
	// fmt.Sprintf создает промежуточную строку
	sb.WriteString(fmt.Sprintf("%d", qtype)) // Для простоты, можно оптимизировать через strconv.AppendUint

	key := sb.String() // Получаем строку

	sb.Reset() // Очищаем builder перед возвратом в пул
	h.builderPool.Put(sb) // Возвращаем builder в пул

	return key
}

// recordError записывает ошибку в статистику (lock-free)
func (h *DNSHandler) recordError(domain string) {
	// Загружаем или создаем атомарный счетчик для домена
	value, loaded := h.errorStats.errors.LoadOrStore(domain, new(int64))
	counterPtr := value.(*int64)

	// Атомарно увеличиваем счетчик
	atomic.AddInt64(counterPtr, 1)

	// Если счетчик был только что создан, увеличиваем общий счетчик ошибок
	// (Это может быть не совсем точный подсчет уникальных доменов из-за гонки,
	// но для метрик приемлемо)
	if !loaded {
		atomic.AddInt64(&h.totalErrors, 1)
	}
}

// isNormalError проверяет, является ли ошибка "нормальной" (не требующей логирования)
func (h *DNSHandler) isNormalError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "Refused") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout")
}

// ServeDNS обрабатывает входящие DNS-запросы
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt64(&h.totalQueries, 1)

	// Получаем сообщение из пула
	m := h.getFromPool()
	m.SetReply(r)
	m.Compress = true
	defer h.putToPool(m) // Возвращаем в пул в конце

	// Проверяем, есть ли вопросы
	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m) // Игнорируем ошибку записи
		return
	}

	question := r.Question[0]
	domain := question.Name
	qtype := question.Qtype

	// Проверяем кэш
	if cachedData, found := h.getCachedResponse(domain, qtype); found {
		atomic.AddInt64(&h.cachedHits, 1)
		// Десериализуем данные из кэша
		cachedMsg := h.getFromPool()
		defer h.putToPool(cachedMsg) // Возвращаем в пул

		if err := cachedMsg.Unpack(cachedData); err != nil {
			log.Printf("ERROR: Failed to unpack cached message for %s: %v", domain, err)
			// Если не удалось десериализовать, считаем промахом и идем дальше
			atomic.AddInt64(&h.cachedMisses, 1) // Компенсируем инкремент hits
			goto resolveUpstream
		}

		// Восстанавливаем ID и EDNS0 из оригинального запроса
		cachedMsg.Id = r.Id
		// EDNS0 уже должен быть в cachedMsg, если он был в оригинальном ответе.
		// Pack/Unpack должны сохранить его.

		// Отправляем ответ из кэша
		_ = w.WriteMsg(cachedMsg) // Игнорируем ошибку записи
		return
	}

	// Кэш не содержит ответа
	atomic.AddInt64(&h.cachedMisses, 1)

resolveUpstream:
	// Создаем запрос для upstream-сервера из пула
	upstreamMsg := h.getFromPool()
	defer h.putToPool(upstreamMsg) // Возвращаем в пул
	upstreamMsg.SetQuestion(domain, qtype)

	// Проверяем, запрашивается ли DNSSEC
	if edns0 := r.IsEdns0(); edns0 != nil {
		upstreamMsg.SetEdns0(edns0.UDPSize(), edns0.Do())
	}

	// Выполняем запрос с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := h.resolver.Exchange(ctx, upstreamMsg)

	// Проверяем ошибки
	if result.Err != nil {
		// Записываем ошибку в статистику
		h.recordError(domain)

		// Логируем только "нестандартные" ошибки
		if !h.isNormalError(result.Err) {
			log.Printf("ERROR resolving %s: %v", domain, result.Err)
		}

		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m) // Игнорируем ошибку записи
		return
	}

	// Копируем данные из ответа
	if result.Msg != nil {
		m.Answer = result.Msg.Answer
		m.Ns = result.Msg.Ns
		m.Extra = result.Msg.Extra

		// Копируем важные флаги
		m.MsgHdr.AuthenticatedData = result.Msg.MsgHdr.AuthenticatedData
		m.MsgHdr.RecursionAvailable = result.Msg.MsgHdr.RecursionAvailable
		m.MsgHdr.Response = result.Msg.MsgHdr.Response
		m.MsgHdr.Authoritative = result.Msg.MsgHdr.Authoritative
		m.Rcode = result.Msg.Rcode

		// EDNS0 должен быть скопирован вместе с Extra.

		// Сохраняем в кэш
		h.cacheResponse(domain, qtype, result.Msg)
	}

	// Отправляем ответ
	_ = w.WriteMsg(m) // Игнорируем ошибку записи
}

func main() {
	// Увеличиваем количество потоков для лучшей производительности
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	// Создаем обработчик
	handler := NewDNSHandler()

	// Создаем DNS-сервер
	// ВАЖНО: Для максимальной производительности, особенно на Linux,
	// рассмотрите возможность использования SO_REUSEPORT.
	server := &dns.Server{
		Addr:    ":5353",
		Net:     "udp",
		Handler: handler,
		UDPSize: defaultUDPPacketSize,
	}

	// Также создаем TCP-сервер для больших ответов
	tcpServer := &dns.Server{
		Addr:    ":5353",
		Net:     "tcp",
		Handler: handler,
	}

	log.Println("Starting optimized DNS server on :5353")
	log.Println("Features: Ristretto Cache ([]byte Zero-Copy), sync.Pool, lock-free stats")
	log.Printf("CPUs: %d", numCPU)

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
	server.Listener.Close()
	tcpServer.Listener.Close()

	log.Println("DNS server stopped")
}
