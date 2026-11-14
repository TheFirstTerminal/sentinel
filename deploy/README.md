# Running Sentinel in front of your app

Sentinel is a reverse proxy: clients talk to Sentinel, Sentinel talks to your
app. Whatever the setup, two rules apply:

1. **Only Sentinel may reach the app.** Close the app's own port to the
   outside (firewall, a private Docker network, a ClusterIP Service).
   Otherwise attackers simply go around Sentinel.
2. **Start in monitor mode** (the default), read what would be blocked for a
   few days, allow any false alarms from the dashboard, then set
   `MODE=protect`.

| Where you run | Use |
|---|---|
| One server with Docker | [`docker/docker-compose.yml`](docker/docker-compose.yml): Sentinel with automatic HTTPS, Redis, a data volume |
| One server without Docker | A release binary and [`systemd/sentinel.service`](systemd/sentinel.service) |
| Kubernetes | [`helm/sentinel`](helm/sentinel): `helm install sentinel ./deploy/helm/sentinel --set config.upstream=http://my-app:3000` |
| Metrics | [`grafana/sentinel.json`](grafana/sentinel.json), a Grafana dashboard for `METRICS_ADDR` |

## With what you already have

**nginx, Caddy or Traefik in front.** Keep them for TLS and static files, and
point their upstream at Sentinel instead of the app:
`proxy_pass http://127.0.0.1:8080;`. Tell Sentinel to trust them, so it sees
the real client address: `TRUSTED_PROXIES=127.0.0.1/32`.

**Instead of nginx.** Sentinel can serve HTTPS itself with Let's Encrypt
(`TLS_AUTO_DOMAINS`, see the Docker example) and route paths to several
apps: `UPSTREAMS=/api/=http://api:8000,/=http://web:3000`.

**Behind Cloudflare or a cloud load balancer.** Set `TRUSTED_PROXIES` to
their address ranges, so `X-Forwarded-For` is believed from them and nobody
else. Without it, every client looks like the load balancer, and one
attacker's ban would ban everyone.

**More than one instance.** Give them all the same `REDIS_URL` (bans and rate
limits are shared) and the same `SENTINEL_SECRET` (dashboard logins stay
valid on every instance).

## The dashboard

Give it its own port (`DASHBOARD_ADDR=:9000`) and don't publish that port
to the internet; reach it through an SSH tunnel or your VPN:
`ssh -L 9000:localhost:9000 your-server`, then open http://localhost:9000.
On the first start Sentinel logs a one-time link (`FIRST RUN`) to create the
admin account.

## Learning your app

`APP_PROFILE=learn` makes Sentinel learn what each page's parameters
normally look like, from requests that pass every other check. After a
few days of normal traffic switch to `detect` (log only), then `block`.
This catches tampering that has no attack syntax, such as letters in an ID
or an over-long field, which rules can't see. Every setting is in
[`docs/configuration.md`](../docs/configuration.md).
