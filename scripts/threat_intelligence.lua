-- threat_intelligence.lua
-- BalanceDNS policy plugin: Threat Intelligence enforcement.
--
-- Contract: on every DNS query this script asks the Go threat-intelligence
-- subsystem (via the sandboxed `threat` module) whether the queried domain is
-- a known threat, and blocks it according to the reputation decision.
--
-- Fail-open: if the `threat` module is unavailable (subsystem disabled or the
-- Lua hook was not registered), every query is FORWARDed. A missing module or a
-- lookup error must never turn a legitimate query into a block — the upstream
-- path decides instead. This matches threat.fail_mode = "open" (the default).
--
-- The block rcode itself (NXDOMAIN / REFUSED / DROP) is chosen in the Go
-- config (plugins.block_rcode); this script stays a pure predicate returning
-- action="BLOCK".

local threat_available = (type(_G.threat) == "table")
  and (type(_G.threat.lookup) == "function")

function handle(question)
  local domain = question.domain or ""
  if domain == "" then
    return { action = "FORWARD" }
  end

  -- No threat module => fail open to normal resolution.
  if not threat_available then
    return { action = "FORWARD" }
  end

  local res = threat.lookup(domain)
  if res == nil then
    -- No match: not a known threat.
    return { action = "FORWARD" }
  end

  if res.block then
    return { action = "BLOCK" }
  end

  -- Matched but observe-only (below reputation threshold): let it resolve; the
  -- telemetry records the sighting.
  return { action = "FORWARD" }
end
