---
lang: ar
title: طرق التركيب
permalink: /ar/setups.html
nav_exclude: true
---

# طرق التركيب

[English](../setups.html)

Sentinel وكيل عكسي (reverse proxy): الطلبات تمشي **الزائر ← (البروكسي أو الـ CDN مالتك) ← Sentinel ← تطبيقك**. هاي الصفحة تشرح الأماكن المعتادة اللي يگعد بيها، وشلون تتأكد يشتغل. الإعدادات مكتوبة كمفاتيح بـ `sentinel.yaml`، وكل واحد إله متغير بيئة ([الإعدادات](configuration.html)).

## هل هو شغال؟

شغّل هذني على العنوان اللي يستخدمه الزوار (بدّل `https://shop.example.com`):

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

إذا الخطوة 3 طلعت عنوان البروكسي أو موزع الحمل مالتك، اضبط `trusted_proxies` مثل اللي جوة. بدونه كل الزوار يبينون IP واحد: حظر مهاجم واحد يحظر الكل، وحدود الطلبات تحسب الكل سوية.

## ورا Nginx (أو Apache، Caddy، Traefik)

خلّي Nginx للشغل اللي يسويه أصلاً (الشهادات، الملفات الثابتة)، ودز الباقي عن طريق Sentinel:

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

(`$connection_upgrade` يحتاج الـ `map $http_upgrade $connection_upgrade { default upgrade; '' close; }` المعتاد ببلوك `http`.)

```yaml
listen: "127.0.0.1:8080"          # only Nginx can reach Sentinel
upstream: http://127.0.0.1:3000   # your app
trusted_proxies: [127.0.0.1/32]   # believe X-Forwarded-For from Nginx only
```

خلّي `Host` مثل ما هو: Sentinel يختار الموقع حسب اسم المضيف، ويمرره لتطبيقك بدون تغيير.

## ورا Cloudflare

Cloudflare يرسل عنوان الزائر بـ `X-Forwarded-For`. صدّقه بس من عناوين Cloudflare نفسها ([القائمة الحالية](https://www.cloudflare.com/ips/)):

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

- **HTTPS:** خلّي وضع SSL بـ Cloudflare على *Full (strict)* وانطي Sentinel [شهادة origin من Cloudflare](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/) (`tls.cert_file`، `tls.key_file`، `tls.listen: ":443"`). الـ HTTPS التلقائي مال Sentinel هم يشتغل ورا Cloudflare، بس شهادة الـ origin أبسط.
- **Cloudflare Tunnel** (`cloudflared`): وجّه النفق على `http://localhost:8080` واضبط `trusted_proxies: [127.0.0.1/32]`.
- سد جدار حماية السيرفر إلا على عناوين Cloudflare، حتى محد يلف من حول Cloudflare ويخربط شوفة Sentinel لمنو يتصل.

## على Kubernetes

الـ chart يشغّل Sentinel كـ Deployment وService. وجّه الـ Ingress مالتك على Sentinel بدل تطبيقك:

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

- الـ chart يصدّق `X-Forwarded-For` من نطاقات الكلستر الخاصة (`trusted_proxies`)، ومنها يرسل الـ Ingress controller.
- إذا عندك نسختين أو أكثر، الحظر وحدود الطلبات ينشاركون بس عن طريق Redis: اضبط `REDIS_URL` (قيمة الـ chart `env`). الحسابات والمفتاح السري: `DATABASE_URL` و`secret.create: true`.
- أكثر من تطبيق: Sentinel واحد يحميهم كلهم بـ `sites` ([أكثر من موقع](configuration.html#several-sites))، وقاعدة Ingress لكل واحد.

### Sentinel نفسه كـ Ingress controller

بدل ما تحط Sentinel ورا ingress controller ثاني، يگدر هو يكون الـ ingress controller: يقرا كل Ingress بيه `ingressClassName: sentinel` ويحمي ويوجّه المضيفين مالته بنفسه.

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

- كل مضيف يصير موقع اسمه `k8s-<namespace>-<ingress>`، ويطلع بلوحة التحكم مثل أي موقع. تغييرات الـ Ingress تنطبق خلال 10 ثواني بدون إعادة تشغيل.
- المسارات بادئات (`Exact` ينعامل كبادئة). المضيف المستخدم من Ingress ثاني أو من ملف الإعدادات ينتجاوز، ويا تحذير بالسجل.
- HTTPS: انهيه عند موزع الحمل مال السحابة، أو استخدم `tls.auto_domains` (أسرار `tls:` مال الـ Ingress ما تنقرا).
- الـ chart ينطي صلاحية قراءة بس: عرض الـ Ingresses، وجلب الـ Services.
- الإعداد: `kubernetes_ingress_class` / `KUBERNETES_INGRESS_CLASS`.

## مباشرة على الإنترنت

ماكو بروكسي گدامه: Sentinel ياخذ المنفذين 80 و443 بنفسه وياخذ شهادات من Let's Encrypt.

```yaml
listen: ":80"
tls:
  auto_domains: [shop.example.com]   # or [sites] for every site's host names
  auto_email: you@example.com
upstream: http://127.0.0.1:3000
```

هنا لا تضبط `trusted_proxies`: الزوار يتصلون بـ Sentinel مباشرة.
