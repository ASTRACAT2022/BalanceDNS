function handle(question)
  local domain = string.lower(question.domain or "")

  if string.match(domain, "^blocked%-by%-lua%.example%.$") then
    return { action = "BLOCK" }
  end

  if string.match(domain, "^rewrite%.example%.$") then
    return {
      action = "REWRITE",
      rewrite_domain = "example.org.",
      rewrite_type = "A"
    }
  end

  if string.match(domain, "^local%.example%.$") then
    return {
      action = "LOCAL_DATA",
      local_data = {
        ttl = 60,
        ips = {"127.0.0.2", "::1"}
      }
    }
  end

  return { action = "FORWARD" }
end
