package main

import (
    "fmt"
    "github.com/miekg/dns"
)

func tempQuery() {
    c := new(dns.Client)
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
    r, _, err := c.Exchange(m, "127.0.0.1:5053")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    fmt.Printf("Query: Got %d answers\n", len(r.Answer))
}
