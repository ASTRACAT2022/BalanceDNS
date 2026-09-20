local blocked_types = {
    ["ANY"] = true,
    ["DNSKEY"] = true,
    ["DS"] = true,
    ["RRSIG"] = true,
    ["NSEC"] = true,
    ["NSEC3"] = true,
    ["NSEC3PARAM"] = true,
    ["CDNSKEY"] = true,
    ["CDS"] = true,
    ["TLSA"] = true,
}

function handle(question)
    local qtype = string.upper(question.type or "")
    
    if blocked_types[qtype] == true then
        return { action = "BLOCK" }
    end
    
    return { action = "FORWARD" }
end
