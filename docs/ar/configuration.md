---
lang: ar
title: الإعدادات
permalink: /ar/configuration.html
nav_exclude: true
---

# الإعدادات

[English](../configuration.html)

Sentinel يقرا إعداداته من ملف YAML، أو من متغيرات البيئة، أو من الاثنين. **متغير البيئة يغلب الملف دائماً**، حتى Docker وKubernetes يگدرون يبدلون إعداد واحد بدون ما يعدلون الملف.

```bash
sentinel init                 # writes a commented sentinel.yaml to start from
sentinel check-config         # checks it without starting (typos are named)
sentinel                      # runs with ./sentinel.yaml if it exists
sentinel --config /path/to/sentinel.yaml
```

الملف ينلگى بـ `--config`، بعدين `SENTINEL_CONFIG`، بعدين `./sentinel.yaml`، بعدين `/etc/sentinel/sentinel.yaml`. أي مفتاح غير معروف يوقف التشغيل ويا اقتراح (`waf.treshold` ← تقصد `WAF_THRESHOLD`؟)، حتى غلطة إملائية ما تطفي حماية بالسكوت.

بالملف، المفاتيح المتداخلة تصير متغير واحد: `waf: {threshold: 7}` هو `WAF_THRESHOLD=7`. القوائم تصير قيم مفصولة بفوارز، والخرائط تصير أزواج `key=value`، و`false` تصير `off`.

## الأساسيات

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `mode` | `MODE` | `monitor` | `monitor`: كل الفحوصات تشتغل وتنسجل، وما ينحجب شي. `protect`: يرفض اللي تمسكه الفحوصات. ابدأ بالمراقبة، اقرا السجل كم يوم، بعدين بدّل. |
| `profile` | `PROFILE` | ماكو | نقطة بداية حسب نوع تطبيقك: `wordpress`، `laravel`، `django`، `nextjs` أو `ai` (شوف جوة) |
| `upstream` | `UPSTREAM_URL` | `http://localhost:3000` | التطبيق اللي يحميه Sentinel |
| `routes` | `UPSTREAMS` | `/` ← `upstream` | أكثر من تطبيق حسب بداية المسار (الأطول يغلب): `{/api/: http://api:8000, /: http://web:3000}`. أكثر من سيرفر لنفس التطبيق يتقاسمون الطلبات بالدور: `{/: [http://web-1:3000, http://web-2:3000]}` (كمتغير: `/=http://web-1:3000\|http://web-2:3000`) |
| `health_check` | `HEALTH_CHECK` | ماكو | مسار يطلبه Sentinel من كل سيرفر كل 10 ثواني، مثلاً `/healthz`. السيرفر اللي يفشل (ما يجاوب أو يرجع 5xx) ما ياخذ طلبات لحد ما ينجح مرة ثانية. والسيرفر اللي يرفض الاتصال ينتجاوز 10 ثواني حتى بدون هذا |
| `sites` | `SITES` | ماكو (موقع واحد لكل الأسماء) | أكثر من موقع أو API حسب اسم المضيف، كل واحد بسيرفراته وإعداداته (كمتغير: JSON): شوف [أكثر من موقع](#several-sites) |
| `listen` | `LISTEN_ADDR` | `:8080` | وين يسمع Sentinel |
| `data_dir` | `DATA_DIR` | `/var/lib/sentinel` بصورة Docker، وإلا `./sentinel-data` | يحفظ اللي لازم يبقى بعد إعادة التشغيل إذا ماكو قاعدة بيانات: المفتاح السري، الحسابات، الاستثناءات، وشهادات HTTPS. خليه على volume. إذا ما ينكتب بيه، Sentinel يگول ويحفظها بالذاكرة |
| `log_format` | `LOG_FORMAT` | تلقائي | `pretty` (سطر مقروء لكل قرار) بالطرفية، و`json` غير ذلك |
| `log_file` | `LOG_FILE` | ماكو | يكتب سجلات JSON هنا هم (`sentinel watch` يقراها) |
| `history_days` | `HISTORY_DAYS` | `30` | أيام سجل لوحة التحكم المحفوظة على القرص، بـ `history/` بمجلد البيانات: كل طلب وقفه Sentinel أو علّم عليه (الطلبات العادية المسموحة ما تنحفظ). يبقى بعد إعادة التشغيل، والأيام القديمة تنمسح، واللوحة تگدر تبحث بيه. `0` يخليه بالذاكرة بس |
| `dashboard` | `DASHBOARD` | شغال | لوحة التحكم، على `/__sentinel/dashboard` (حسابات بتحقق بخطوتين؛ شوف *حسابات لوحة التحكم* جوة) |
| `dashboard_listen` | `DASHBOARD_ADDR` | ماكو (على المنفذ الرئيسي) | انطي اللوحة منفذ خاص، مثلاً `:9000`: وقتها تنفتح على `http://<host>:9000` وما توصلها أبداً من المنفذ العام. ننصح تخلي هذا المنفذ خاص (جدار حماية أو VPN). حظر الـ IP ما ينطبق عليه، فالمدير اللي يشارك عنوان ويا مهاجم (شبكة مكتب أو موبايل) يگدر يدخل ويشيل الحظر؛ وتسجيل الدخول هناك يبقى عليه حد |
| `security_headers` | `SECURITY_HEADERS` | شغال | يضيف nosniff وReferrer-Policy وX-Frame-Options و(على HTTPS) HSTS إذا التطبيق ما يضيفهن |
| `timezone` | `TZ` | `UTC` | المنطقة الزمنية لأوقات السجل اللي تطلع للناس |

### حسابات لوحة التحكم

رابط التشغيل الأول يسوي أول **مدير** (admin). المدراء يضيفون حسابات أكثر من بطاقة **Accounts** باللوحة، كل حساب بدور:

| الدور | يگدر |
|---|---|
| `admin` | كل شي، ومنها المواقع والتنبيهات والحسابات |
| `operator` | يحظر ويشيل الحظر، يسمح بالإنذارات الكاذبة، يعيد تحميل القواعد؛ ويشوف كل شي |
| `viewer` | يشوف كل شي، وما يغير شي |

الحساب الجديد ياخذ كلمة سر لمرة وحدة، تطلع مرة وحدة للمدير اللي سواه، ويضبط التحقق بخطوتين بأول دخول. **Reset** ينطي كلمة سر جديدة لمرة وحدة ويعيد ضبط التحقق بخطوتين (موبايل ضايع). تغيير الدور أو حذف الحساب يصير فوراً. يبقى دائماً مدير واحد على الأقل، ومحد يگدر يحذف أو ينزّل حسابه هو.

## أكثر من موقع {#several-sites}

Sentinel واحد يگدر يحمي أكثر من موقع وAPI، يختارها حسب اسم المضيف بكل طلب. كل موقع إله سيرفراته، ويگدر يكون إله وضعه، ووضع جدار الحماية، ووضع التعلم الآلي، وحدود الطلبات، وفحص الصحة الخاص بيه؛ وأي شي ما يحدده الموقع ياخذه من الإعداد العام.

```yaml
mode: protect
sites:
  - name: shop
    hosts: [shop.example.com, www.shop.example.com]
    upstreams: [http://shop-1:3000, http://shop-2:3000]   # shared in turn
    health_check: /healthz
    rate_limits: { /login: 10/1m, /: 600/1m }
  - name: api
    hosts: [api.example.com]
    routes: { /v2/: http://api-v2:8000, /: http://api:8000 }
    mode: monitor            # new API: watch it for a while first
  - name: others
    hosts: ["*.example.com"] # any other subdomain
    upstreams: [http://static:80]
```

| مفتاح الموقع | المعنى |
|---|---|
| `name` | حروف إنكليزية صغيرة، أرقام و`-`. يطلع بالسجلات وباللوحة |
| `hosts` | أسماء بالضبط (`shop.example.com`)، أو wildcards (`*.example.com`، الأطول يغلب)، أو `*` لأي مضيف ماله موقع ثاني |
| `upstreams` | السيرفرات لـ `/`؛ أكثر من واحد يتقاسمون الطلبات |
| `routes` | حسب بداية المسار داخل الموقع، مثل `routes` العام |
| `health_check`، `mode`، `waf_mode`، `ml_mode`، `rate_limits` | مثل الإعدادات العامة، بس لهذا الموقع. حدود الطلبات تنحسب لكل موقع |
| `api_spec_file`، `api_spec_prefix` | ملف OpenAPI مال هذا الموقع والمسار اللي يغطيه، بدل `api_spec` العام. الاثنين سوية أو لا واحد |
| `prompt_guard_paths`، `prompt_canary` | نقاط محادثة الذكاء الاصطناعي مال هذا الموقع (والكلمة السرية)، بدل `prompt_guard` العام |

الطلب اللي اسم مضيفه ما يطابق أي موقع ياخذ `421 Misdirected Request` وينسجل؛ ضيف موقع بـ `hosts: ["*"]` حتى يمسك الباقي بدلها. صفحات Sentinel نفسه (اللوحة وتسجيل دخولها) تشتغل على كل مضيف. كمتغير بيئة، `SITES` هو نفس القائمة بصيغة JSON: `SITES='[{"name":"shop","hosts":["shop.example.com"],"upstreams":["http://shop:3000"]}]'`.

**تعديل موقع من اللوحة.** زر **Edit** بكل موقع يغير الوضع، ووضع جدار الحماية، ووضع التعلم الآلي، وحدود الطلبات، وأسماء المضيف، والسيرفرات، وفحص الصحة، وSentinel شغال. التغييرات تتفحص مثل ملف الإعدادات (اسم مضيف مستخدم بموقعين، سيرفر مو رابط) وتنرفض ويا السبب. تنحفظ بـ `site-settings.json` بمجلد البيانات وتغلب ملف الإعدادات؛ **Back to the config file** يشيلها.

**Add site** يسوي موقع جديد (الاسم، أسماء المضيف، السيرفرات، وفحص صحة اختياري). يبدأ بوضع المراقبة وينحفظ بـ `sites-added.json` بمجلد البيانات. المواقع المضافة هناك تنحذف من هناك؛ ومواقع ملف الإعدادات تنحذف من الملف.

### القوالب (Profiles)

القالب يعبي إعدادات تناسب نوع معين من التطبيقات. أي شي تضبطه انت يبقى يغلب، وتگدر تشوف شنو يسوي كل قالب بالضبط بـ [`gateway/internal/config/profiles.go`](https://github.com/TheFirstTerminal/sentinel/blob/main/gateway/internal/config/profiles.go).

| القالب | شنو يسوي |
|---|---|
| `wordpress` | يشيل فخاخ `/wp-admin` و`/wp-login.php` (هناك هي صفحات حقيقية، فالمدراء راح ينحظرون)، يحط حد على `wp-login.php` و`xmlrpc.php`، ويسمح بالـ HTML والكود بمحررات المقالات والقوالب والإضافات |
| `laravel` | كوكيز `laravel_session` / `XSRF-TOKEN` المشفرة وحقل `_token` ما تنحسب هجمات؛ يحط حد على `/login` و`/password/` |
| `django` | نفس الشي لـ `csrftoken` و`csrfmiddlewaretoken` و`sessionid`؛ يحط حد على دخول الإدارة والحسابات |
| `nextjs` | نموذج التعلم الآلي يتجاوز ملفات البناء `/_next/`؛ كوكيز NextAuth ما تنحسب هجمات؛ يحط حد على `/api/auth/` |
| `ai` | يشغّل الحماية من حقن الأوامر على `/api/chat` و`/api/generate` (Ollama) ونقاط `/v1/...` بأسلوب OpenAI وAnthropic |

## كشف الهجمات

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `waf.mode` | `WAF_MODE` | `block` | داخل وضع الحماية: `block`، أو `detect` حتى بس يسجل اللي يلگاه جدار الحماية |
| `waf.threshold` | `WAF_THRESHOLD` | `5` | درجة الشذوذ اللي تنحسب هجوم (التطابق الخطير درجته 5) |
| `waf.second_opinion` | `WAF_SECOND_OPINION` | شغال | إذا بس قواعد OWASP علّمت على الطلب، ودرجتها مو أعلى من الحد، ونموذج التعلم الآلي متأكد 95% على الأقل إن كل قيمة علّمت عليها سليمة، الطلب ينسجل كـ `detected` بدل ما ينحجب. هذا يشيل الإنذارات الكاذبة المعتادة من CRS ("Node.js & Express"، "phone case (large)") وقواعد Sentinel وتطابقات CRS الواضحة تبقى تحجب. يحتاج `ml.mode` يكون detect أو block. `off` يحجب كل كشف من CRS |
| `waf.rules_file` | `RULES_FILE` | المدمجة | بدّل قواعد Sentinel بملف JSON |
| `waf.crs` | `CRS_DIR` | شغال إذا مدمج (صورة Docker)، وإلا مطفي | قواعد OWASP Core Rule Set: `on`، `off`، أو مسار مجلد `rules/` مال CRS |
| `waf.crs_paranoia` | `CRS_PARANOIA` | `1` | من `1` (إنذارات كاذبة قليلة) لـ `4` (صارم؛ توقع تحتاج ضبط) |
| `waf.crs_exclude` | `CRS_EXCLUDE` | `920220` | أرقام قواعد CRS أو نطاقات تنطفي، مثلاً `[920220, 942100-942199]` |
| `exclusions_file` | `EXCLUSIONS_FILE` | `exclusions.yaml` بمجلد البيانات | قائمة استثناءات YAML: قاعدة مطفية لمسار و/أو حقل واحد. زر "Allow…" باللوحة يضيف عليها؛ شوف جوة |
| `waf.max_field_bytes` | `WAF_MAX_FIELD_BYTES` | `65536` | أي حقل أو header أو body خام أكبر من هذا ينرفض (قاعدة BODY-003)؛ `0` = مطفي |
| `waf.max_inspect_ms` | `WAF_MAX_INSPECT_MS` | `5000` | الطلب اللي يشغل قواعد OWASP أطول من هذا ينرفض (قاعدة BODY-004)، حتى كم طلب مصنوع ما يوقفون البوابة. والـ body اللي حجمه 64 KB أو أكثر ينفحص بالدور (نص المعالجات بالكثير بنفس الوقت)، حتى ما يبطّئ الطلبات العادية؛ والـ body الكبير اللي يبقى ينتظر لحد ما يخلص الوقت ينرفض بنفس الطريقة. الوقت ينحسب كوقت فعلي، فعلى سيرفر مضغوط هواية، رفع ملف كبير وسليم ممكن يوصله: زيده إذا BODY-004 طلع على طلبات حقيقية؛ `0` = مطفي |
| `max_body_bytes` | `MAX_BODY_BYTES` | `1048576` | الـ body الأكبر ينرفض بـ 413: ما ينگدر ينفحص كامل |
| `app_profile` | `APP_PROFILE` | `off` | **تعلّم تطبيقك.** `learn`: Sentinel يتعلم، من الطلبات اللي عبرت كل الفحوصات، شلون تكون معاملات كل صفحة عادةً (الطول، الحروف، الأرقام، القيم الثابتة). `detect` / `block`: يعلّم على أو يرفض الطلبات اللي ما تطابق، وهذا يمسك التلاعب بالمعاملات اللي ما بيه صيغة هجوم. ينحفظ بمجلد البيانات. على بيانات CSIC 2010 مسك 96.6% من الهجمات ويا 0.01% إنذارات كاذبة ([ml-report](../ml-report.html)) |
| `app_profile_min_seen` | `APP_PROFILE_MIN_SEEN` | `20` | الصفحة أو الحقل لازم ينشافون هالعدد قبل ما القالب يحكم عليهم |
| `ml.mode` | `ML_MODE` | `detect` | مصنّف التعلم الآلي: `off`، `detect` (تسجيل بس) أو `block` |
| `ml.threshold` | `ML_THRESHOLD` | `0.9` | الاحتمال اللي ينحسب هجوم |
| `ml.skip_paths` | `ML_SKIP_PATHS` | ماكو | بدايات مسارات النموذج يتجاهلها (مثلاً `[/socket.io/]`) |
| `prompt_guard.paths` | `PROMPT_GUARD_PATHS` | ماكو | نقاط محادثة الذكاء الاصطناعي اللي تنحمى من حقن الأوامر |
| `prompt_guard.mode` | `PROMPT_GUARD_MODE` | `block` | `block` أو `detect` |
| `prompt_guard.threshold` | `PROMPT_GUARD_THRESHOLD` | `5` | الدرجة اللي تنحسب حقن |
| `prompt_guard.canary` | `PROMPT_CANARY` | ماكو | كلمة سرية بالتعليمات المخفية مال الذكاء الاصطناعي مالتك؛ أي رد بيه هاي الكلمة (حتى لو مشفرة) ينحجز |
| `honeypot.paths` | `HONEYPOT_PATHS` | قائمة مدمجة | مسارات فخاخ (`/.env`، `/wp-admin`...)؛ اللي يدوسها ينحظر الـ IP مالته |
| `honeypot.ban_minutes` | `HONEYPOT_BAN_MINUTES` | `60` | شگد يطول الحظر من دوسة فخ، أو من إغراق بالطلبات |

**ليش 920220 مطفية افتراضياً.** قاعدة CRS رقم 920220 تدور على ترميز URL مزدوج، وهم تنطلق على أي `%` حرفية بالاستعلام، مثل بحث عن "50% off". الـ normalizer مال Sentinel أصلاً يفك الترميز المكرر، فالقاعدة تضيف إنذارات كاذبة وتقريباً ما تكشف شي (مقاسة بـ [الاختبارات](../benchmarks.html)). اضبط `CRS_EXCLUDE` على شي ثاني، أو على قائمة فارغة، حتى تغير هذا.

### الاستثناءات (تصليح الإنذارات الكاذبة)

إذا قاعدة حجبت شي سليم، طفي هاي القاعدة **بس بالمكان اللي تغلط بيه**، مو بكل مكان. اضغط "Allow…" على الطلب باللوحة، أو اكتب الملف بإيدك:

```yaml
- rule: CRS-942100          # or SQLI-001, ML, PI-001, or a prefix like CRS-942*
  path: /api/reviews        # requests whose path starts with this
  field: comment            # only this field (query, form, JSON, header or cookie name)
  note: reviews can mention SQL words
```

كل سطر يحتاج مسار أو حقل (أو الاثنين)، حتى ما تنطفي قاعدة بكل مكان بالغلط. `method:` يضيّقه أكثر، و`site:` (اسم من `sites`) يحصره بموقع واحد؛ بدونه السطر ينطبق على كل المواقع. "Allow…" يعبي موقع الطلب. الملف ينقرا من جديد ويا `SIGHUP`.

## شنو يرجّع التطبيق

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `response_check` | `RESPONSE_CHECK` | `block` (`detect` بوضع المراقبة) | يفحص ردود التطبيق إذا بيها تسريب: أخطاء قاعدة البيانات، stack traces، مفاتيح خاصة ومفاتيح سحابة، قوائم مجلدات (تنحجز بـ `block`، وتنسجل بـ `detect`)، وأرقام بطاقات الدفع (تنخفى دائماً إلا آخر أربع أرقام). `off` يطفيه |
| `response_max_bytes` | `RESPONSE_MAX_BYTES` | `1048576` | الردود النصية لحد هالحجم تنفحص. الأكبر، والثنائية، والمتدفقة (SSE، أي شي يسوي flush) تعبر بدون فحص، حتى التدفق ما ينكسر أبداً |

خطأ قاعدة البيانات بالرد هو غالباً أول علامة إن الحقن ديشتغل، فحجزه ياخذ من المهاجم الإشارة اللي يعتمد عليها. حتى تسمح بنوع تسريب لبعض المسارات (سيرفر ملفات يعرض المجلدات بقصد)، ضيف استثناء برقم الكشف، مثلاً `rule: LEAK-LISTING`، `path: /files/`، `field: response`.

## البوتات

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `bot.block_scanners` | `BOT_BLOCK_SCANNERS` | شغال | يرفض الطلبات اللي الـ User-Agent مالها يسمي أداة هجوم (sqlmap، nikto، nuclei، wpscan...) |
| `bot.challenge` | `BOT_CHALLENGE` | `off` | فحص JavaScript للمتصفحات: `suspicious` (عملاء يبينون آليين: بدون User-Agent، متصفحات headless أو أدوات أتمتة، "متصفح" بدون Accept-Language) أو `all` (كل زائر على المسارات جوة). بس تحميل الصفحات ينفحص (`GET` يطلب HTML)، لأن بس المتصفح اللي يحمّل صفحة يگدر يشغّل الفحص: طلبات الـ API، والصور، والعملاء اللي ما يطلبون HTML يكملون للفحوصات الثانية بدونه |
| `bot.challenge_paths` | `BOT_CHALLENGE_PATHS` | `/` | وين ينطبق الفحص، مثلاً `[/login, /signup]` |
| `bot.strict_paths` | `BOT_STRICT_PATHS` | ماكو | مسارات كل عميل بيها يحتاج تصريح فحص المتصفح، مثلاً `[/login, /signup]`: المتصفح اللي يحمّل الصفحة ياخذ الفحص، وأي شي ثاني بدون تصريح (سكربتات، curl، فورم ينرسل بدون تحميل صفحته) ينرفض (قاعدة BOT-STRICT). يشتغل حتى لو `bot.challenge` مطفي. بس للصفحات اللي الناس يوصلوها بالمتصفح: تطبيقات الموبايل، والـ webhooks، وعملاء الـ API ما يگدرون ياخذون تصريح |
| `bot.difficulty` | `BOT_DIFFICULTY` | `15` | حجم إثبات العمل؛ المتصفح يحتاج تقريباً 0.1–0.5 ثانية على 15، وكل درجة زيادة تضاعفه |

الفحص إثبات عمل قصير: المتصفح يحله مرة وياخذ كوكي موقّعة لمدة 24 ساعة، مربوطة بالـ IP والـ User-Agent مالته. الطلبات اللي ما تطلب صفحة HTML (API، صور) ما ينطلعلها فحص أبداً، فالـ API تبقى تشتغل. خلّك واقعي بشنو يوقف: السكربتات والبوتات البسيطة، مو مهاجم مصر يسوق متصفح حقيقي (المتصفحات headless الحديثة تبين مثل العادية). ويا `all`، محركات البحث ما تگدر تفهرس المسارات المفحوصة، فاستخدمه لصفحات مثل `/login`، مو للموقع كله.

## حدود الطلبات والشبكة

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `rate_limits` | `RATE_LIMITS` | `{/__sentinel/auth/: 10/1m, /: 600/1m}` | عدد الطلبات بكل فترة حسب بداية المسار؛ المستخدمين المسجلين ينحسبون بالاسم. `off` يطفيه. العميل اللي يرسل 3 أضعاف حده خلال فترة وحدة يعتبر إغراق وينحظر الـ IP مالته (`honeypot.ban_minutes`) |
| `login_fail_limit` | `LOGIN_FAIL_LIMIT` | `10` | محاولات الدخول الفاشلة لكل حساب (من أي IP) قبل توقف 15 دقيقة؛ `0` = مطفي |
| `redis_url` | `REDIS_URL` | ماكو (بالذاكرة) | مشاركة العدادات والحظر بين نسخ Sentinel |
| `trusted_proxies` | `TRUSTED_PROXIES` | ماكو | نطاقات CIDR مال موزع الحمل مالتك؛ بس `X-Forwarded-For` منهم ينصدّق |
| `trust_proxy_headers` | `TRUST_PROXY_HEADERS` | `false` | صدّق `X-Forwarded-For` من أي أحد (بس إذا محد يوصل لـ Sentinel غير البروكسي مالتك) |
| `geo.file` | `GEOIP_FILE` | ماكو | ملف CSV بصيغة `cidr,country` (حوّل أي قاعدة بيانات IP-إلى-بلد) |
| `geo.deny_countries` | `GEO_DENY_COUNTRIES` | ماكو | مثلاً `[KP]` |
| `geo.allow_countries` | `GEO_ALLOW_COUNTRIES` | ماكو | إذا انضبط، بس هذني البلدان (والعناوين الخاصة) |
| `ip.deny` / `ip.allow` | `IP_DENY` / `IP_ALLOW` | ماكو | نطاقات CIDR تنرفض دائماً / الوحيدة المسموحة |

## المراقبة والتنبيهات

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `metrics_listen` | `METRICS_ADDR` | مطفي | يقدم مقاييس Prometheus على `http://<this>/metrics`، مثلاً `:9090`. منفذ منفصل، حتى ما تكون عامة على المنفذ الرئيسي أبداً |
| `alerts.webhook_url` | `ALERT_WEBHOOK_URL` | مطفي | وين تروح التنبيهات: webhook مال Slack أو Discord، أو رابط تيليغرام `https://api.telegram.org/bot<token>/sendMessage`، أو أي رابط (ينرسل JSON) |
| `alerts.telegram_chat_id` | `ALERT_TELEGRAM_CHAT_ID` | ماكو | المحادثة اللي ينرسل إلها، لتيليغرام |
| `alerts.burst` | `ALERT_BURST` | `20` | عدد الطلبات الموقوفة من IP واحد خلال دقيقة اللي تسوي تنبيه "موجة هجوم" |
| `export.syslog` | `EXPORT_SYSLOG` | مطفي | يرسل الأحداث الأمنية لسيرفر syslog (RFC 5424، facility *log audit*): `udp://host:514`، `tcp://host:601` أو `tls://host:6514` |
| `export.otlp` | `EXPORT_OTLP` | مطفي | يرسل الأحداث الأمنية لـ OpenTelemetry collector كسجلات (OTLP على HTTP، JSON)، مثلاً `http://otel-collector:4318` |
| `export.otlp_headers` | `EXPORT_OTLP_HEADERS` | ماكو | headers تنرسل للـ collector، مثلاً `api-key=...` (أكثر من واحد: `A=1,B=2`) |
| `export.all` | `EXPORT_ALL` | `false` | يصدّر الطلبات العادية المسموحة هم، مو بس المحجوبة والمعلّمة وأحداث الدخول |
| `kubernetes_ingress_class` | `KUBERNETES_INGRESS_CLASS` | مطفي | يكون الـ Ingress controller مال Kubernetes لهاي الفئة (مثلاً `sentinel`): المواقع تجي من الـ Ingresses. شوف [طرق التركيب](setups.html) |

التنبيهات تنرسل على: دوسة فخ، موجة هجوم من IP واحد، تخمين كلمة سر حساب، حساب مدير جديد، وفشل إعادة تحميل. كل موضوع ينبّه مرة وحدة بالكثير كل 10 دقايق، وبالمجموع 20 تنبيه بالدقيقة بالكثير، حتى الهجوم ما يغرق موبايلك.

بطاقة **Alerts** باللوحة تضبط الـ webhook ومحادثة تيليغرام وحجم الموجة وSentinel شغال (تنحفظ بـ `alerts.json` بمجلد البيانات، وتغلب ملف الإعدادات)، وتگدر تطفي التنبيهات.

الأحداث المصدّرة بيها النتيجة، وIP العميل، والطريقة، والمسار، والحالة، والقاعدة، والسبب، والموقع، والبلد، والمستخدم، ورقم الطلب، حتى أي SIEM (Splunk، Elastic، Graylog، Wazuh، Grafana Loki عن طريق collector) يگدر يبحث وينبّه عليها. الإرسال ما يبطّئ الطلبات أبداً: إذا الطرف الثاني واگف، الأحداث تنرمى والعدد ينسجل كل دقيقة.

المقاييس: `sentinel_requests_total{outcome}`، `sentinel_rule_stops_total{rule}`، `sentinel_request_duration_seconds` (histogram)، `sentinel_bans_active`، `sentinel_rules_loaded`، `sentinel_exclusions`، `sentinel_info{version,mode}`، ويا مدة التشغيل والذاكرة والـ goroutines. لوحة Grafana جاهزة موجودة بـ [`deploy/grafana/sentinel.json`](https://github.com/TheFirstTerminal/sentinel/blob/main/deploy/grafana/sentinel.json).

## دخول لوحة التحكم، مخطط الـ API، وHTTPS

| مفتاح الملف | المتغير | الافتراضي | المعنى |
|---|---|---|---|
| `secret` | `SENTINEL_SECRET` | يتسوّى مرة وينحفظ بمجلد البيانات | المفتاح الرئيسي لرموز دخول اللوحة وأسرار التحقق بخطوتين المشفرة، 32 حرف على الأقل (`openssl rand -hex 32`) |
| `database_url` | `DATABASE_URL` | ماكو (الحسابات بمجلد البيانات) | PostgreSQL لحسابات المدراء والرموز الملغية |
| `api_spec.file` / `api_spec.prefix` | `API_SPEC_FILE` / `API_SPEC_PREFIX` | مطفي | مواصفات OpenAPI 3، بـ JSON أو YAML؛ الطلبات اللي ما تطابقها تنرفض |
| `tls.auto_domains` | `TLS_AUTO_DOMAINS` | ماكو | **HTTPS تلقائي**: شهادات من Let's Encrypt لهذني الدومينات، تتجدد تلقائياً، مثلاً `[shop.example.com]`. الكلمة `sites` تعني كل اسم مضيف بالضبط بكل موقع (`[sites]` تغطيهم كلهم). المنفذين 80 و443 لازم يوصلوهم من الإنترنت؛ والـ HTTP العادي يتحول لـ HTTPS |
| `tls.auto_email` | `TLS_AUTO_EMAIL` | ماكو | إيميل للتواصل ويا Let's Encrypt (تحذيرات الانتهاء) |
| `tls.auto_cache` | `TLS_AUTO_CACHE` | `certs` بمجلد البيانات | المجلد اللي تنحفظ بيه الشهادات (خليه على volume، وإلا حدود Let's Encrypt تنطبق ويا كل إعادة تشغيل) |
| `tls.listen` | `TLS_LISTEN_ADDR` | ماكو (`:443` ويا HTTPS التلقائي) | مثلاً `:8443` حتى يقدم HTTPS هم |
| `tls.cert_file` / `tls.key_file` | `TLS_CERT_FILE` / `TLS_KEY_FILE` | ماكو | شهادة السيرفر ومفتاحها |

تسجيل الدخول لتطبيقاتك، وسياسات الوصول (RBAC/ABAC)، وmTLS للخدمات، والتحقق الإضافي حسب الخطر، وسجل التدقيق اللي ما ينلعب بيه، كلها جزء من Sentinel Pro. إذا انضبط أي واحد من إعداداتها (`POLICY_FILE`، `MTLS_ROUTES`، `AUDIT_LOG_FILE`، ...)، النسخة المجانية ترفض تشتغل وتگول السبب، بدل ما تشتغل بالسكوت بدون الحماية اللي انت متوقعها.
