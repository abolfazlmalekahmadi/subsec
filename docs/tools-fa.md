# راهنمای ابزارهای پلتفرم sybsec (فارسی)

این سند توضیح می‌ده هر ابزار توی این SOC **چیه**، **چرا اینجاست**، و **چه کارهایی** باهاش می‌شه کرد. ابزارها بر اساس لایه‌های معماری مرتب شدن.

> آدرس سرور دمو: `167.88.165.161`. همه‌ی URLها رو با این IP باز کن.

---

## نمای کلی: جریان داده

```
endpointها/شبکه ──► Wazuh agent / Suricata ──► Kafka ──► Logstash ──► Elasticsearch
                                  │                                         │
                                  ├──► Wazuh Manager (قوانین تشخیص)         ├──► Kibana (کاوش)
                                  │         │                               └──► Grafana (داشبورد)
                                  │         ├──► MISP (آیا این IoC بدنامه؟)
                                  │         ├──► Shuffle (پاسخ خودکار) ──► firewall-api + TheHive
                                  │         └──► ML service (آیا ناهنجاره؟)
                                  └──◄ Caldera (حمله‌ی شبیه‌سازی برای تست تشخیص)
```

ایده‌ی کلی: یه رویداد امنیتی → نرمال‌سازی می‌شه → با قانون/ML تشخیص داده می‌شه → با threat intel غنی می‌شه → خودکار پاسخ داده می‌شه (بلاک + case) → و به‌صورت دوره‌ای با red team اعتبارسنجی می‌شه.

---

## لایه ۱ — جمع‌آوری داده و سنسورها

### 🛡️ Wazuh Agent
- **چیه:** نرم‌افزاری که روی هر endpoint (لینوکس/ویندوز) نصب می‌شه.
- **چرا:** چشم و گوشِ ما روی خود سرورهاست.
- **چه کاری می‌شه کرد:**
  - **FIM** (File Integrity Monitoring): هر تغییر فایل توی مسیرهای حساس رو با diff می‌گیره.
  - جمع‌آوری لاگ auth، اجرای دستورات (auditd)، Windows Event Logs.
  - اجرای **active-response** (مثل بلاک IP، کشتن پروسه).
- **دمو:** `docker exec sybsec-wazuh-agent-01 ...` — agent ما با ID `001` فعاله. هر فایلی که توی `/var/sybsec-watch` بسازی → FIM روی WUI نشون می‌ده.

### 🔍 Suricata
- **چیه:** IDS/IPS شبکه — ترافیک رو می‌خونه و حمله‌ها رو با امضا (rule) تشخیص می‌ده.
- **چرا:** لایه‌ی تشخیص شبکه (اسکن، C2، exfil).
- **چه کاری:** خروجی EVE JSON می‌ده که می‌ره توی Kafka. در prod به SPAN port وصل می‌شه.

### 📨 Filebeat + Kafka
- **چیه:** Filebeat لاگ‌ها رو از سنسورها برمی‌داره و می‌ریزه توی **Kafka** (صف پیام مطمئن).
- **چرا:** انتقال مطمئن و مقیاس‌پذیر — اگه Logstash کند بشه، داده توی Kafka نگه داشته می‌شه.
- **چه کاری:** ۷ تاپیک داریم (zeek-logs، suricata-alerts، wazuh-events، ...).

---

## لایه ۲ — ذخیره‌سازی و نرمال‌سازی

### 🗄️ Elasticsearch + Kibana
- **چیه:** Elasticsearch موتور ذخیره/جستجوی همه‌ی رویدادهاست؛ Kibana رابط کاوششه.
- **چرا:** همه‌ی داده توی یه جا با یه اسکیما (**ECS**) → correlation ممکن می‌شه.
- **چه کاری:**
  - **Kibana → Discover** → دیتاویوهای `sybsec security-wazuh / security-suricata / security-anomalies`.
  - جستجو مثل `rule.id:100010` یا `source.ip:203.0.113.66`.
- **آدرس:** `http://167.88.165.161:5601` (elastic / changeme_elastic)

### ⚙️ Logstash
- **چیه:** خط لوله‌ی پردازش — از Kafka می‌خونه، به ECS تبدیل می‌کنه، می‌ریزه توی ES.
- **چرا:** هر سنسور فرمت خودش رو داره؛ Logstash همه رو یک‌دست می‌کنه (مثلاً `src_ip` → `source.ip`).
- **چه کاری:** ۴ pipeline داریم (zeek/suricata/wazuh/sysmon) + GeoIP enrichment.

---

## لایه ۳ — موتورهای تشخیص

### 📏 Wazuh Manager (تشخیص قانون‌محور)
- **چیه:** مغز قوانین — لاگ‌ها رو decode و با ۱۵٬۰۰۰+ قانون تطبیق می‌ده.
- **چرا:** تشخیص سریع و دقیقِ حمله‌های شناخته‌شده.
- **چه کاری:**
  - قوانین سفارشی ما (`wazuh/rules/local_rules.xml`): brute force (100010)، malware (100002)، lateral movement (100030)، exfil (100040)، ML anomaly bridge (100050/51)، MISP match (100020).
  - هر قانون به **MITRE ATT&CK** map شده.
  - **دمو:** `./scripts/demo.sh bruteforce` → روی **WUI** قانون 100010 رو ببین.
- **آدرس WUI:** `https://167.88.165.161:5602` (admin / SecretPassword)

### 🤖 سرویس ML Anomaly (تشخیص ناهنجاری)
- **چیه:** میکروسرویس Python (FastAPI) که با **PyOD + ADTK** ناهنجاری رو تشخیص می‌ده.
- **چرا:** چیزهایی که هیچ قانونی براشون نوشته نشده — رفتار غیرعادی.
- **چه کاری:**
  - `POST /score` با یه رویداد → `anomaly_score` + دلیل + ویژگی‌های مقصر.
  - ensemble از IsolationForest + HBOS + LOF.
  - **دمو:** `./scripts/demo.sh anomaly` → یه رویداد exfil در ساعت ۳ صبح score=1.0 می‌گیره.
- **آدرس:** `http://167.88.165.161:8088/health`

### 📊 Grafana
- **چیه:** داشبوردهای متریک و SLA.
- **چرا:** دید لحظه‌ای مدیریتی (نرخ alert، روند anomaly، MTTD/MTTR).
- **چه کاری:** ۴ داشبورد (SOC Overview، ML Anomaly، Network، MTTD/MTTR).
- **آدرس:** `http://167.88.165.161:3000` (admin / changeme_grafana)

---

## لایه ۴ — هوش تهدید (Threat Intelligence)

### 🌐 MISP
- **چیه:** پلتفرم اشتراک هوش تهدید — پایگاه‌داده‌ای از IoCها (IP/هش/دامنه‌ی بدنام).
- **چرا:** «این IP که الان دیدم، قبلاً جای دیگه بدنام بوده؟»
- **چه کاری:**
  - feedهای عمومی (CIRCL، Abuse.ch، OTX) رو می‌کشه.
  - **یکپارچگی Wazuh→MISP (زنده):** هر alert با IP/هش → query به MISP → اگه match شد، فیلد `threat_intel.misp` اضافه و قانون **100020** به **CRITICAL** ارتقا می‌ده.
  - **دمو (تأییدشده):** SSH از IP بدنام `203.0.113.66` → match در MISP → escalate به CRITICAL.
- **آدرس:** `http://167.88.165.161:8087` (admin@sybsec.local / Sybsec-Misp-2026!)

### 🧬 OpenCTI — *(فعلاً design-only)*
- **چیه:** پلتفرم correlation هوش تهدید + map کامل ATT&CK.
- **وضعیت:** configها آماده‌ست ولی deploy نشده چون ~۸GB RAM می‌خواد و این باکس swap نداره. هدف prod/Helm.

---

## لایه ۵ — مدیریت رخداد (Case Management)

### 📋 TheHive
- **چیه:** پلتفرم مدیریت case — برای هر هشدار مهم یه پرونده می‌سازه.
- **چرا:** آنالیست به‌جای جستجو، مستقیم روی یه case ساختاریافته کار می‌کنه.
- **چه کاری:**
  - ساخت خودکار case (از Wazuh مستقیم یا از Shuffle).
  - template برای هر نوع حمله، تایم‌لاین SLA، observableها.
  - **دمو:** بعد از brute force، توی **Cases** پرونده‌های `[Brute Force]` و `[SOAR]` رو ببین.
- **آدرس:** `http://167.88.165.161:9000` (admin@thehive.local / secret)

### 🔬 Cortex
- **چیه:** موتور اجرای **analyzer** — observableها رو غنی می‌کنه (VirusTotal، AbuseIPDB، Shodan، GeoIP).
- **چرا:** آنالیست با یه کلیک reputation یه IP/هش رو می‌گیره.
- **چه کاری:** analyzer روی هر observable case اجرا می‌شه (نیاز به API key واقعی برای سرویس‌های خارجی).
- **آدرس:** `http://167.88.165.161:9001`

---

## لایه ۶ — پاسخ خودکار (SOAR)

### 🔀 Shuffle
- **چیه:** موتور اتوماسیون بصری (SOAR) — workflowهایی که خودکار اجرا می‌شن.
- **چرا:** پاسخ بدون دخالت انسان — سرعت (MTTR < ۱۰ دقیقه).
- **چه کاری (زنده — workflow «PB2» چهارمرحله‌ای):**
  1. **geoip** → کشور/ISP مهاجم از ip-api.com
  2. **block** → IP رو توی firewall-api بلاک می‌کنه
  3. **case** → case غنی‌شده توی TheHive می‌سازه
  4. **notify** → خلاصه‌ی SOC
  - **دمو:** `./scripts/demo.sh bruteforce` → توی **Workflows → PB2 → Executions** هر ۴ نود سبز.
- **آدرس:** `http://167.88.165.161:3001` (admin@sybsec.local / sybsec-shuffle-admin)

### 🧱 firewall-api
- **چیه:** یه سرویس کوچیک که نقش API فایروال (مثل pfSense alias) رو بازی می‌کنه.
- **چرا:** هدفِ قابل‌تأییدِ بلاک برای Shuffle (در prod جاش pfSense می‌شینه).
- **چه کاری:** `POST /block` و `GET /blocklist`. — `./scripts/demo.sh blocklist`
- **آدرس:** `http://167.88.165.161:8099/blocklist`

### Wazuh Active-Response
- **چیه:** اسکریپت‌هایی که Wazuh خودکار اجرا می‌کنه وقتی قانونی شلیک شد.
- **چه کاری:** `sybsec-blocklist.sh` روی قانون 100010 → IP رو به blocklist اضافه می‌کنه (مستقل از Shuffle، موازی).

---

## لایه ۷ — اعتبارسنجی Red Team

### 🎯 MITRE Caldera
- **چیه:** پلتفرم شبیه‌سازی حریف — حمله‌های واقعی ATT&CK رو اجرا می‌کنه.
- **چرا:** «آیا تشخیص‌های ما واقعاً کار می‌کنن؟» — تست پوشش تشخیص.
- **چه کاری (زنده — تأییدشده):**
  - یه agent (sandcat) روی endpoint مانیتورشده اجرا شد.
  - ability سفارشی «sybsec FIM tamper» اجرا شد → فایل ساخت → **Wazuh با قانون 554 تشخیصش داد**.
  - هر ability که Wazuh تشخیص نده = «detection gap» → تیکت backlog.
- **آدرس:** `http://167.88.165.161:8888` (red / کلید توی `docker logs caldera`)

---

## 🎬 سناریوی بزرگ — زنجیره‌ی کامل حمله (همه‌ی سرویس‌ها)

```bash
./scripts/scenario-apt.sh
```
یه حمله‌ی APT چندمرحله‌ای که **همه‌ی لایه‌ها** رو با هم درگیر می‌کنه و هرکدوم رو زنده تأیید می‌کنه:
شناسایی (Suricata) → دسترسی اولیه (Wazuh brute force) → هوش تهدید (MISP → CRITICAL) →
استقرار (Caldera → FIM) → استخراج داده (ML anomaly) → پاسخ خودکار (Shuffle: بلاک + case) → اعتبارسنجی.

## فرمان‌های مفید دمو

```bash
./scripts/demo.sh preflight    # چک سلامت همه‌ی سرویس‌ها
./scripts/demo.sh bruteforce   # حمله‌ی brute force → تشخیص + پاسخ خودکار
./scripts/demo.sh fim          # دستکاری فایل → FIM
./scripts/demo.sh webattack    # SQLi → تشخیص وب
./scripts/demo.sh anomaly      # ناهنجاری ML
./scripts/demo.sh suricata     # alert شبکه
./scripts/demo.sh blocklist    # IPهای بلاک‌شده (Wazuh + firewall-api)
./scripts/demo.sh all          # همه با هم
```

سند کامل ارائه‌ی استپ‌به‌استپ: `docs/DEMO.md`
ساختار و معماری کامل: `docs/architecture.md`
وضعیت صادقانه‌ی هر بخش: `STATUS.md`

---

## خلاصه‌ی یک‌خطی هر ابزار

| ابزار | یک جمله |
|------|---------|
| Wazuh Agent | چشم‌وگوش روی endpoint (FIM، لاگ، پاسخ) |
| Suricata | IDS شبکه (تشخیص حمله با امضا) |
| Kafka | صف پیام مطمئن بین سنسور و ذخیره‌سازی |
| Logstash | نرمال‌سازی همه‌ی لاگ‌ها به یک اسکیما (ECS) |
| Elasticsearch | ذخیره و جستجوی همه‌ی رویدادها |
| Kibana | کاوش خام رویدادها |
| Wazuh Manager | موتور تشخیص قانون‌محور + ATT&CK |
| ML Service | تشخیص ناهنجاری (چیزی که قانون نداره) |
| Grafana | داشبورد متریک و SLA |
| MISP | پایگاه IoC + غنی‌سازی هشدارها |
| TheHive | مدیریت پرونده‌ی رخداد |
| Cortex | اجرای analyzer روی observableها |
| Shuffle | اتوماسیون پاسخ (SOAR) |
| firewall-api | هدف بلاک قابل‌تأیید |
| Caldera | شبیه‌سازی حمله برای تست تشخیص |
