package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type input struct {
	Question struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
		QType  uint16 `json:"qtype"`
	} `json:"question"`
}

type output struct {
	Action    string     `json:"action"`
	LocalData *localData `json:"local_data,omitempty"`
}

type localData struct {
	IPs []string `json:"ips,omitempty"`
	TTL uint32   `json:"ttl,omitempty"`
}

func main() {
	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v", err)
		os.Exit(1)
	}

	in := input{}
	if err := json.Unmarshal(payload, &in); err != nil {
		fmt.Fprintf(os.Stderr, "invalid input json: %v", err)
		os.Exit(1)
	}

	out := output{Action: "FORWARD"}
	domain := strings.ToLower(in.Question.Domain)
	if strings.HasSuffix(domain, "go-local.example.") {
		out.Action = "LOCAL_DATA"
		out.LocalData = &localData{IPs: []string{"127.0.0.42"}, TTL: 30}
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v", err)
		os.Exit(1)
	}
}
