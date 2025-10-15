package main

import (
	// "fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
	goresolver "github.com/peterzen/goresolver"
)

// handleDNSRequest processes incoming DNS requests.
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range r.Question {
			log.Printf("Received query for %s (type %s)", q.Name, dns.TypeToString[q.Qtype])
			// Use the global resolver to answer the query
			// This assumes the resolver is properly initialized
			if goresolver.CurrentResolver != nil {
				response, err := goresolver.CurrentResolver.Query(q.Name, q.Qtype)
				if err == nil && response != nil {
					m.Answer = append(m.Answer, response.Answer...)
					m.Ns = append(m.Ns, response.Ns...)
					m.Extra = append(m.Extra, response.Extra...)
				} else {
					log.Printf("Error resolving %s: %v", q.Name, err)
					// If resolution fails, return a SERVFAIL or NXDOMAIN
					m.SetRcode(r, dns.RcodeServerFailure)
				}
			} else {
				log.Println("Resolver not initialized, returning SERVFAIL")
				m.SetRcode(r, dns.RcodeServerFailure)
			}
		}
	}

	w.WriteMsg(m)
}

// StartDNSServer starts the DNS server on the specified address and port.
func StartDNSServer(addr string) {
	dns.HandleFunc(".", handleDNSRequest)

	server := &dns.Server{Addr: addr, Net: "udp"}
	log.Printf("Starting DNS server on %s", addr)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n", err.Error())
	}
}

func main() {
	port := "5053"
	addr := net.JoinHostPort("0.0.0.0", port)

	// Initialize the resolver
	res, err := goresolver.NewResolver("/etc/resolv.conf")
	if err != nil {
		log.Fatalf("Failed to initialize resolver: %v", err)
	}
	goresolver.CurrentResolver = res // Set the global resolver instance

	go StartDNSServer(addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s.String())
	res.Stop()
}