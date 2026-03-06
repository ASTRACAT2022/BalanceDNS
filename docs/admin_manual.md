# AstracatDNS Administrator Manual

## 1. Admin Panel Access

Enable in `config.yaml`:

```yaml
admin_addr: "0.0.0.0:8080"
admin_username: "admin"
admin_password: "change_me"
```

Open:

```text
http://<server>:8080
```

## 2. Available Admin APIs

- `GET /api/metrics` - dashboard snapshot
- `POST /api/control/reload` - reload resolver
- `POST /api/control/cache/clear` - clear cache

## 3. Operational Checklist

- Restrict access to `admin_addr` via firewall/reverse proxy
- Use strong admin credentials
- Keep TLS cert/key valid when using DoT/ODoH
- Monitor `/metrics` from Prometheus

## 4. Plugin Operations

Current operational plugins:

- `hosts` (local overrides)
- `adblock` (blocklist-based filtering)
- `dnsdist_compat` (dnsdist-like policy chain for recursive mode)
- `odoh` (oblivious DNS endpoint)

## 5. Security Notes

- `drop_any_queries` and attack protection limits should stay enabled in production
- `dnssec_validate: true` is recommended
- `dnssec_fail_closed: true` is recommended for strict mode

## 6. Removed Functionality

Cluster admin/node sync endpoints are not part of this version.
