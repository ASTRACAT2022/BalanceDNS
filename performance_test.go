package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	fmt.Println("=== Тестирование производительности DNS-сервера ===")

	// Адрес DNS-сервера
	serverAddr := "127.0.0.1:5053"
	
	// Список доменов для тестирования
	domains := []string{
		"google.com",
		"github.com",
		"stackoverflow.com",
		"amazon.com",
		"wikipedia.org",
		"youtube.com",
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"reddit.com",
	}

	fmt.Println("Тест 1: Одиночные запросы")
	singleQueryTest(serverAddr, domains[0])

	fmt.Println("\nТест 2: Последовательные запросы")
	sequentialTest(serverAddr, domains)

	fmt.Println("\nТест 3: Параллельные запросы")
	parallelTest(serverAddr, domains, 10)

	fmt.Println("\nТест 4: Высокая нагрузка (100 параллельных)")
	parallelTest(serverAddr, domains, 100)

	fmt.Println("\nТестирование производительности завершено.")
}

func singleQueryTest(serverAddr, domain string) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	start := time.Now()
	r, _, err := c.Exchange(m, serverAddr)
	duration := time.Since(start)

	if err != nil {
		log.Printf("Ошибка запроса: %v", err)
	} else if r != nil && len(r.Answer) > 0 {
		fmt.Printf("Запрос %s: %v, время: %v, ответ: %s\n", domain, r.Rcode == dns.RcodeSuccess, duration, r.Answer[0].String())
	} else {
		fmt.Printf("Запрос %s: %v, время: %v, нет ответа\n", domain, r != nil && r.Rcode == dns.RcodeSuccess, duration)
	}
}

func sequentialTest(serverAddr string, domains []string) {
	c := new(dns.Client)
	totalTime := time.Duration(0)
	successCount := 0

	for i, domain := range domains {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		m.RecursionDesired = true

		start := time.Now()
		r, _, err := c.Exchange(m, serverAddr)
		duration := time.Since(start)
		totalTime += duration

		if err == nil && r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			successCount++
			if i < 3 { // Показать первые 3 результата
				fmt.Printf("  %s: OK, %v\n", domain, duration)
			}
		} else {
			if i < 3 {
				fmt.Printf("  %s: FAIL, %v\n", domain, duration)
			}
		}
	}

	avgTime := totalTime / time.Duration(len(domains))
	fmt.Printf("  Успешно: %d/%d, Среднее время: %v\n", successCount, len(domains), avgTime)
}

func parallelTest(serverAddr string, domains []string, workers int) {
	c := new(dns.Client)
	var wg sync.WaitGroup
	results := make(chan bool, len(domains)*2)
	start := time.Now()

	// Создаем пулы воркеров
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := workerID; i < len(domains)*2; i += workers {
				domain := domains[i%len(domains)]
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
				m.RecursionDesired = true

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				r, _, err := c.ExchangeContext(ctx, m, serverAddr)
				results <- (err == nil && r != nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0)
			}
		}(w)
	}

	// Закрываем канал результатов после завершения всех воркеров
	go func() {
		wg.Wait()
		close(results)
	}()

	// Подсчитываем результаты
	successCount := 0
	for result := range results {
		if result {
			successCount++
		}
	}

	duration := time.Since(start)
	qps := float64(len(domains)*2) / duration.Seconds()
	
	fmt.Printf("  Результат: %d/%d успешно, время: %v, QPS: %.2f\n", 
		successCount, len(domains)*2, duration, qps)
}