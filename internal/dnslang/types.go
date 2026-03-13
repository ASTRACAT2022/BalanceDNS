package dnslang

import "github.com/miekg/dns"

type Phase string

const (
	PhasePreflight Phase = "preflight"
	PhasePolicy    Phase = "policy"
)

type SetKind string

const (
	SetStrings  SetKind = "strings"
	SetDomains  SetKind = "domains"
	SetSuffixes SetKind = "suffixes"
	SetIPSet    SetKind = "ipset"
	SetIPPool   SetKind = "ippool"
	SetHosts    SetKind = "hosts"
)

type ActionKind string

const (
	ActionDrop        ActionKind = "drop"
	ActionRefuse      ActionKind = "refuse"
	ActionNXDOMAIN    ActionKind = "nxdomain"
	ActionEmpty       ActionKind = "empty"
	ActionAnswer      ActionKind = "answer"
	ActionSpoof       ActionKind = "spoof"
	ActionLoadBalance ActionKind = "load_balance"
)

type Program struct {
	Sets  []SetDecl
	Rules []RuleSpec
}

type SetDecl struct {
	Name   string
	Source SetSource
}

type SetSource struct {
	Kind   SetKind
	Path   string
	Values []string
}

type RuleSpec struct {
	Name    string
	Phase   Phase
	RawWhen string
	When    Expr
	Action  ActionSpec
}

type ActionSpec struct {
	Kind     ActionKind
	Type     uint16
	Value    string
	SetName  string
	TTL      uint32
	Strategy string
}

type EvalContext struct {
	Transport string
	ClientIP  string
}

type Result struct {
	Handled  bool
	Drop     bool
	Response *dns.Msg
	Action   string
	Rule     string
}

type Expr interface {
	eval(*evalEnv) bool
}

type evalEnv struct {
	engine   *Engine
	ctx      EvalContext
	req      *dns.Msg
	question dns.Question
}

type valueKind int

const (
	valueScalar valueKind = iota
	valueList
)

type valueNode struct {
	Kind valueKind
	Text string
	List []valueNode
}

type binaryExpr struct {
	Op    string
	Left  Expr
	Right Expr
}

type unaryExpr struct {
	Op   string
	Expr Expr
}

type conditionExpr struct {
	Field      string
	Comparator string
	Value      valueNode
}
