-- BalanceDNS Lua example component
-- Logs query metadata and leaves packets unchanged.

function balancedns_pre_query(packet)
    local qname = balancedns.qname(packet) or "<unknown>"
    local qtype = balancedns.qtype(packet) or -1
    local tid = balancedns.tid(packet) or -1
    balancedns.log(string.format(
        "pre_query tid=%d qtype=%d qname=%s len=%d",
        tid,
        qtype,
        qname,
        balancedns.len(packet) or 0
    ))

    -- nil means "do not modify packet"
    return nil, false
end

function balancedns_post_response(packet)
    local qname = balancedns.qname(packet) or "<unknown>"
    local rcode = balancedns.rcode(packet) or -1
    balancedns.log(string.format(
        "post_response qname=%s rcode=%d len=%d",
        qname,
        rcode,
        balancedns.len(packet) or 0
    ))

    return nil, false
end
