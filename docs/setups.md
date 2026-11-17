# Common setups

Sentinel is a reverse proxy: traffic goes **visitor → (your proxy or CDN) →
Sentinel → your app**. This page covers the usual places it sits, and how to
check it works. Settings are written as `sentinel.yaml` keys; each also has
an environment variable ([configuration](configuration.md)).

## Is it working?

Run these against the address visitors use (replace `https://shop.example.com`):

```bash
# 1. Sentinel answers
curl -s https://shop.example.com/__sentinel/health
# {"status":"ok","mode":"monitor",...}

# 2. It sees attacks: in monitor mode this still reaches your app,
#    and the dashboard's console shows it as DETECTED (WOULD BLOCK)
curl -s -o /dev/null -w "%{http_code}\n" "https://shop.example.com/?q=1'+UNION+SELECT+password+FROM+users--"

# 3. It sees the real visitor's IP: open the dashboard's console and check
#    the IP of your own request is your public IP, not your proxy's.
```

If step 3 shows your proxy's or load balancer's address, set
`trusted_proxies` as below. Without it, every visitor looks like one IP: one
attacker's ban would block everyone, and rate limits would count everyone
together.

## Behind Nginx (or Apache, Caddy, Traefik)

Keep Nginx for what it already does (certificates, static files), and send
the rest through Sentinel:

```nginx
location / {
    proxy_pass         http://127.0.0.1:8080;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    # WebSockets
    proxy_http_version 1.1;
    proxy_set_header   Upgrade    $http_upgrade;
    proxy_set_header   Connection $connection_upgrade;
}
```

(`$connection_upgrade` needs the usual `map $http_upgrade $connection_upgrade
{ default upgrade; '' close; }` in the `http` block.)

```yaml
listen: "127.0.0.1:8080"          # only Nginx can reach Sentinel
upstream: http://127.0.0.1:3000   # your app
trusted_proxies: [127.0.0.1/32]   # believe X-Forwarded-For from Nginx only
```

Keep `Host` as shown: Sentinel picks the site by host name, and passes it
on to your app unchanged.

## Behind Cloudflare

Cloudflare sends the visitor's address in `X-Forwarded-For`. Trust it only
from Cloudflare's own addresses ([current list](https://www.cloudflare.com/ips/)):

```yaml
trusted_proxies:
  - 173.245.48.0/20
  - 103.21.244.0/22
  - 103.22.200.0/22
  - 103.31.4.0/22
  - 141.101.64.0/18
  - 108.162.192.0/18
  - 190.93.240.0/20
  - 188.114.96.0/20
  - 197.234.240.0/22
  - 198.41.128.0/17
  - 162.158.0.0/15
  - 104.16.0.0/13
  - 104.24.0.0/14
  - 172.64.0.0/13
  - 131.0.72.0/22
  - 2400:cb00::/32
  - 2606:4700::/32
  - 2803:f800::/32
  - 2405:b500::/32
  - 2405:8100::/32
  - 2a06:98c0::/29
  - 2c0f:f248::/32
```

- **HTTPS:** set Cloudflare's SSL mode to *Full (strict)* and give Sentinel
  a [Cloudflare origin certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)
  (`tls.cert_file`, `tls.key_file`, `tls.listen: ":443"`). Sentinel's own
  automatic HTTPS also works behind Cloudflare, but an origin certificate
  is simpler.
- **Cloudflare Tunnel** (`cloudflared`): point the tunnel at
  `http://localhost:8080` and set `trusted_proxies: [127.0.0.1/32]`.
- Lock the server's firewall to Cloudflare's addresses, so nobody can go
  around Cloudflare and Sentinel's view of who is calling.

## On Kubernetes

The chart runs Sentinel as a Deployment and a Service. Point your Ingress
at Sentinel instead of your app:

```bash
helm install sentinel ./deploy/helm/sentinel --set config.upstream=http://my-app:3000
```

```yaml
# your Ingress: send traffic to Sentinel, not to the app
spec:
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: sentinel
                port: { number: 80 }   # the chart's Service port
```

- The chart already trusts `X-Forwarded-For` from the cluster's private
  ranges (`trusted_proxies`), which is where your Ingress controller sends
  from.
- With two or more replicas, bans and rate limits are shared only through
  Redis: set `REDIS_URL` (chart value `env`). Accounts and the secret
  key: `DATABASE_URL` and `secret.create: true`.
- Several apps: one Sentinel can protect them all with `sites`
  ([several sites](configuration.md#several-sites)), one Ingress rule each.

### Sentinel as the Ingress controller

Instead of putting Sentinel behind another ingress controller, it can be
the ingress controller: it reads every Ingress with
`ingressClassName: sentinel` and protects and routes its hosts itself.

```bash
helm install sentinel ./deploy/helm/sentinel \
  --set ingressController.enabled=true --set service.type=LoadBalancer
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
  annotations:
    sentinel.io/mode: protect        # optional; default: the global mode
spec:
  ingressClassName: sentinel
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: shop, port: { number: 3000 } } }
          - path: /api/
            pathType: Prefix
            backend: { service: { name: shop-api, port: { name: http } } }
```

- Each host becomes a site named `k8s-<namespace>-<ingress>`, shown on the
  dashboard like any other. Changes to Ingresses apply within 10 seconds,
  without a restart.
- Paths are prefixes (`Exact` is treated as a prefix). A host already used
  by another Ingress or by the config file is skipped, with a warning in
  the log.
- HTTPS: terminate it at your cloud load balancer, or use `tls.auto_domains`
  (Ingress `tls:` secrets are not read).
- The chart grants read-only access: list Ingresses, get Services.
- Setting: `kubernetes_ingress_class` / `KUBERNETES_INGRESS_CLASS`.

## Directly on the internet

No proxy in front: Sentinel takes ports 80 and 443 itself and gets
certificates from Let's Encrypt.

```yaml
listen: ":80"
tls:
  auto_domains: [shop.example.com]   # or [sites] for every site's host names
  auto_email: you@example.com
upstream: http://127.0.0.1:3000
```

No `trusted_proxies` here: visitors connect to Sentinel directly.
