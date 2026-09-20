// mock_upstream is a minimal, fast local DNS upstream for load testing.
// It responds to every A query with a fixed answer.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/miekg/dns"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:15354", "listen address")
	flag.Parse()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) > 0 {
			q := req.Question[0]
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 1),
				})
			}
		}
		_ = w.WriteMsg(resp)
	})

	udp := &dns.Server{Addr: *addr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: *addr, Net: "tcp", Handler: mux}

	go func() { log.Fatal(udp.ListenAndServe()) }()
	go func() { log.Fatal(tcp.ListenAndServe()) }()

	log.Printf("mock upstream listening on %s (udp+tcp)", *addr)
	select {}
}
