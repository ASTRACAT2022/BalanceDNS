package dnsproxy

type ProxyRewriteRule struct {
	Domain string
	Type   string
	Value  string
	TTL    uint32
}

type ProxyLoadBalancerTarget struct {
	Value  string
	Weight int
}

type ProxyLoadBalancerRule struct {
	Domain   string
	Type     string
	Strategy string
	TTL      uint32
	Targets  []ProxyLoadBalancerTarget
}

type ProxyPolicyOptions struct {
	Enabled        bool
	BlockedDomains []string
	RewriteRules   []ProxyRewriteRule
	LoadBalancers  []ProxyLoadBalancerRule
}

type ProxyOptions struct {
	EnableAttackProtection bool
	MaxGlobalInflight      int
	MaxQPSPerIP            int
	RateLimitBurstPerIP    int
	MaxConcurrentPerIP     int
	MaxQuestionsPerRequest int
	MaxQNameLength         int
	DropANYQueries         bool
	Policy                 ProxyPolicyOptions
}

func DefaultProxyOptions() ProxyOptions {
	return ProxyOptions{
		EnableAttackProtection: true,
		MaxGlobalInflight:      4096,
		MaxQPSPerIP:            300,
		RateLimitBurstPerIP:    600,
		MaxConcurrentPerIP:     200,
		MaxQuestionsPerRequest: 1,
		MaxQNameLength:         253,
		DropANYQueries:         true,
		Policy: ProxyPolicyOptions{
			Enabled:        true,
			BlockedDomains: []string{},
			RewriteRules:   []ProxyRewriteRule{},
			LoadBalancers:  []ProxyLoadBalancerRule{},
		},
	}
}
