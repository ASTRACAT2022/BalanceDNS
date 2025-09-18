package main

import (
	"context"
	"dns-resolver/internal/resolver"
	"fmt"
	"github.com/miekg/dns"
)

func main() {
	domainsToTest := []string{
		"verisign.com",      // Should be secure
		"example.com",       // Should be insecure
		"dnssec-failed.org", // Should be bogus (fail)
	}

	r := resolver.NewResolver()

	for _, domain := range domainsToTest {
		fmt.Printf("\n--- Тестируем домен: %s ---\n", domain)

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		msg.SetEdns0(4096, true)

		result := r.Exchange(context.Background(), msg)

		fmt.Println("--- DNS Response ---")
		if result.Msg != nil {
			fmt.Printf("Rcode: %s, AD bit: %v\n", dns.RcodeToString[result.Msg.Rcode], result.Msg.AuthenticatedData)
		}

		if result.Err != nil {
			fmt.Println("--- Error ---")
			fmt.Println(result.Err)
		}
	}
}
