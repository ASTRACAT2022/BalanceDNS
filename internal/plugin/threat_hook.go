package plugin

import (
	"balancedns/internal/threat"

	lua "github.com/yuin/gopher-lua"
)

// ThreatLookup is the Go callback that the sandboxed `threat.lookup()` Lua
// function invokes on every query. It must be cheap and never panic; the engine
// runs it inside the protect call path so a panic is caught, not fatal.
type ThreatLookup interface {
	// Lookup answers a threat check for one query domain. Match=false means "no
	// threat"; Block tells the policy whether to block.
	Lookup(query string) threat.LookupOutcome
}

// NewThreatLuaHook returns a LuaHook that registers a read-only `threat` module
// into each fresh sandboxed Lua state. When lookup is nil, the hook is a no-op
// (the policy sees no `threat` global and must fall back to FORWARD).
//
// The exposed Lua API (minimal, backward-compatible):
//
//	-- returns nil when no match, else a table:
//	threat.lookup("evil.packetsdk.io.")
//	  -> nil
//	  -> { matched=true, block=true, reason="high_confidence",
//	       category="botnet_c2", base="packetsdk.io", sources={"c2-feed"} }
func NewThreatLuaHook(lookup ThreatLookup) LuaHook {
	if lookup == nil {
		return nil
	}
	return func(L *lua.LState) {
		mdl := L.NewTable()

		lookupFn := L.NewFunction(func(L *lua.LState) int {
			q := L.CheckString(1)
			out := lookup.Lookup(q)
			if !out.Match {
				L.Push(lua.LNil)
				return 1
			}
			t := L.NewTable()
			t.RawSetString("matched", lua.LBool(out.Match))
			t.RawSetString("block", lua.LBool(out.Block))
			t.RawSetString("reason", lua.LString(out.Reason))
			if out.Category != "" {
				t.RawSetString("category", lua.LString(out.Category))
			}
			if out.Matched != "" {
				t.RawSetString("base", lua.LString(out.Matched))
			}
			if len(out.Sources) > 0 {
				so := L.NewTable()
				for _, s := range out.Sources {
					so.Append(lua.LString(s))
				}
				t.RawSetString("sources", so)
			}
			L.Push(t)
			return 1
		})
		mdl.RawSetString("lookup", lookupFn)

		L.SetGlobal("threat", mdl)
	}
}
