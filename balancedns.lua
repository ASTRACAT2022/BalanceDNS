local public_ip = "144.31.151.64"

return {
    server = {
        udp_listen = public_ip .. ":53",
        tcp_listen = public_ip .. ":53",
        dot_listen = public_ip .. ":853",
        doh_listen = public_ip .. ":443",
    },

    tls = {
        cert_pem = "/var/lib/balancedns/tls/server.crt",
        key_pem = "/var/lib/balancedns/tls/server.key",
    },

    balancing = {
        algorithm = "fastest",
    },

    security = {
        deny_any = true,
        deny_dnskey = true,
        request_timeout_ms = 500,
    },

    cache = {
        enabled = true,
        max_size = 100000,
        ttl_seconds = 7200,
        min_ttl = 60,
        max_ttl = 86400,
        decrement_ttl = true,
    },

    metrics = {
        listen = "127.0.0.1:9100",
    },

    global = {
        threads_udp = 8,
        threads_tcp = 4,
        max_tcp_clients = 4096,
        max_waiting_clients = 200000,
        max_active_queries = 100000,
        max_clients_waiting_for_query = 4096,
    },

    hosts_local = {
        --["example.com."] = "1.2.3.4",
    },

    hosts_remote = {
        url = "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/main/bypass",
        refresh_seconds = 3600,
        ttl_seconds = 3600,
    },

    plugins = {
        libraries = {},
    },

    lua = {
        scripts = {},

        settings = {
            --mode = "observe",
            --sample_rate = 100,
        },

        sandbox = {
            max_packet_bytes = 4096,
            disable_after_failures = 8,
            init_instruction_limit = 500000,
            hook_instruction_limit = 100000,
        },

        components = {
            --{
            --    path = "/var/lib/balancedns/lua/policy.lua",
            --    enabled = true,
            --    settings = {
            --        mode = "block",
            --        reply_ip = "127.0.0.1",
            --    },
            --},
        },
    },

    wasm = {
        sandbox = {
            max_packet_bytes = 4096,
            disable_after_failures = 8,
        },

        components = {
            --{
            --    path = "/var/lib/balancedns/wasm/remote_hosts_plugin.wasm",
            --    enabled = true,
            --},
        },
    },

    upstreams = {
        {
            name = "upstream-1",
            proto = "udp",
            addr = "95.85.95.85:53",
            pool = "default",
            weight = 5,
        },
        {
            name = "upstream-2",
            proto = "udp",
            addr = "2.56.220.2:53",
            pool = "default",
            weight = 5,
        },
        {
            name = "upstream-yandex",
            proto = "udp",
            addr = "77.88.8.8:53",
            pool = "ru-zone",
            weight = 1,
        },
    },

    routing_rules = {
        {
            suffix = ".",
            upstreams = { "upstream-1", "upstream-2" },
        },
        {
            suffix = ".ru.",
            upstreams = { "upstream-yandex" },
        },
    },
}
