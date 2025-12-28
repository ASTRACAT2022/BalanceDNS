package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const (
	TargetHost = "https://dns.astracat.ru"
	ConfigPath = "/odohconfigs"
	QueryPath  = "/dns-query"
)

func main() {
	// 1. Fetch configs
	fmt.Printf("Fetching ODoH configs from %s%s...\n", TargetHost, ConfigPath)
	resp, err := http.Get(TargetHost + ConfigPath)
	if err != nil {
		log.Fatalf("Failed to fetch configs: %v", err)
	}
	defer resp.Body.Close()

	configBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read configs: %v", err)
	}

	configs, err := odoh.UnmarshalObliviousDoHConfigs(configBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal configs: %v", err)
	}
	if len(configs.Configs) == 0 {
		log.Fatalf("No configs found")
	}
	fmt.Printf("Received %d ODoH config(s). Using the first one.\n", len(configs.Configs))

	// 2. Prepare DNS Query
	target := "google.com."
	fmt.Printf("Preparing ODoH query for %s A record...\n", target)

	msg := new(dns.Msg)
	msg.SetQuestion(target, dns.TypeA)
	msg.RecursionDesired = true
	packedDNS, err := msg.Pack()
	if err != nil {
		log.Fatalf("Failed to pack DNS message: %v", err)
	}

	// 3. Encrypt Query (Oblivious Query)
	odohQuery := odoh.CreateObliviousDNSQuery(packedDNS, 0)
	config := configs.Configs[0].Contents

	encryptedQuery, queryContext, err := config.EncryptQuery(odohQuery)
	if err != nil {
		log.Fatalf("Failed to encrypt query: %v", err)
	}

	serializedQuery := encryptedQuery.Marshal()

	// 4. Send Request
	fmt.Printf("Sending encrypted query (%d bytes) to %s%s...\n", len(serializedQuery), TargetHost, QueryPath)

	req, err := http.NewRequest("POST", TargetHost+QueryPath, bytes.NewReader(serializedQuery))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	client := &http.Client{}
	qResp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer qResp.Body.Close()

	if qResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(qResp.Body)
		log.Fatalf("Server returned error %d: %s", qResp.StatusCode, string(body))
	}

	respBody, err := io.ReadAll(qResp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	fmt.Printf("Received encrypted response (%d bytes).\n", len(respBody))

	// 5. Decrypt Response
	odohRespMsg, err := odoh.UnmarshalDNSMessage(respBody)
	if err != nil {
		log.Fatalf("Failed to unmarshal response message: %v", err)
	}

	decryptedBytes, err := queryContext.DecryptResponse(odohRespMsg)
	if err != nil {
		log.Fatalf("Failed to decrypt response: %v", err)
	}

	// 5b. Unmarshal Oblivious Response Body
	obliviousResp, err := odoh.UnmarshalResponseBody(decryptedBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal oblivious response body: %v", err)
	}

	// 6. Parse DNS Response
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(obliviousResp.Message()); err != nil {
		log.Fatalf("Failed to unpack DNS response: %v", err)
	}

	fmt.Printf("✅ Success! Answer:\n%s\n", dnsResp.String())
}
