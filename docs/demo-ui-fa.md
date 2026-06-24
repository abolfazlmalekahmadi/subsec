# راهنمای نمایش UI در دمو (فارسی)

این سند می‌گه موقع دمو **توی هر UI دقیقاً چی رو باز کنی و به چی اشاره کنی**.
مهاجم سناریو: `203.0.113.66` (IP بدنام در MISP) → قربانی: `10.0.0.5`.

## قبل از شروع
```bash
./scripts/demo.sh preflight        # همه سبز؟
./scripts/demo.sh reset            # تمیزکاری
./scripts/scenario-apt.sh          # شلیک کل زنجیره
```
بعد ۶ تب مرورگر باز کن (همه با IP سرور `167.88.165.161`).

---

## 1️⃣ Wazuh WUI — قلب تشخیص
**https://167.88.165.161:5602** — `admin` / `SecretPassword`

- **Threat Hunting** (یا Security events) → توی سرچ بزن `data.srcip:203.0.113.66`
  - 👉 نشون بده: rule **5710** (تلاش لاگین) چند بار، بعد **5712** (brute force)، بعد **100010** (rule سفارشی ما).
  - 👉 روی alert کلیک کن → پایین **MITRE: T1110** رو نشون بده.
- سرچ `rule.id:100020`
  - 👉 این alert **CRITICAL** ـه: «MISP IoC match». نشون بده فیلد **`threat_intel.misp`** که میگه این IP توی MISP بدنام بوده.
- ماژول **MITRE ATT&CK** (منوی چپ)
  - 👉 تکنیک‌های روشن‌شده: Credential Access (T1110)، Initial Access.
- ماژول **Integrity Monitoring** → فایل `caldera-attack.conf`
  - 👉 این رو **Caldera** ساخت و Wazuh با rule **554** گرفتش. نشون بده agent = `sybsec-endpoint-01`.
- منوی **Agents**
  - 👉 یه endpoint واقعی (`sybsec-endpoint-01`) با وضعیت **Active**.

---

## 2️⃣ MISP — هوش تهدید
**http://167.88.165.161:8087** — `admin@sybsec.local` / `Sybsec-Misp-2026!`

- **Events** → event «sybsec demo - known bad C2»
  - 👉 attribute رو نشون بده: `203.0.113.66` نوع `ip-dst` با تگ `to_ids`.
  - 👉 بگو: «همینه که Wazuh بهش query زد و alert رو CRITICAL کرد.»

---

## 3️⃣ Shuffle — پاسخ خودکار (SOAR)
**http://167.88.165.161:3001** — `admin@sybsec.local` / `sybsec-shuffle-admin`

- **Workflows → PB2 — Brute Force Response**
  - 👉 گراف ۴ نودی قشنگ: `geoip → block → case → notify`.
- تب **Executions** (یا آیکون run history) → آخرین اجرا رو باز کن
  - 👉 هر ۴ نود **سبز** (SUCCESS). روی هر نود کلیک کن:
    - **geoip**: کشور/ISP مهاجم.
    - **block**: پاسخ firewall-api (`blocked: true`).
    - **case**: شماره‌ی case که توی TheHive ساخت.
    - **notify**: خط خلاصه‌ی SOC.

---

## 4️⃣ TheHive — مدیریت پرونده
**http://167.88.165.161:9000** — `admin@thehive.local` / `secret`

- **Cases** (مطمئن شو org `sybsec` انتخاب شده)
  - 👉 پرونده‌ی **`[SOAR] Brute force from 203.0.113.66 (...)`** — این رو **Shuffle خودکار** ساخت.
  - 👉 بازش کن: توی description ببین **GeoIP + وضعیت بلاک + MITRE T1110**.
  - 👉 پرونده‌ی `[Brute Force …]` هم هست (مسیر مستقیم Wazuh→TheHive).
  - 👉 بگو: «آنالیست به‌جای جستجو، یه پرونده‌ی آماده با همه‌ی context داره.»

---

## 5️⃣ Grafana — داشبورد و متریک
**http://167.88.165.161:3000** — `admin` / `changeme_grafana`

- داشبورد **sybsec — SOC Overview**
  - 👉 «Total alerts» بالا رفته، «Alert rate by module»، «Top source IPs» (203.0.113.66 بالاست).
- داشبورد **sybsec — ML Anomaly Scores**
  - 👉 نمودار score که به **1.0** پریده (رویداد exfil) + جدول anomalyهای اخیر.
- داشبورد **sybsec — Network Traffic**
  - 👉 alertهای Suricata (اسکن SSH).

> اگه خالی بود: time picker رو روی **Last 1 hour / 24 hours** بذار و refresh کن.

---

## 6️⃣ Kibana — کاوش خام (ECS)
**http://167.88.165.161:5601** — `elastic` / `changeme_elastic`

- **Discover** → دیتاویو **`sybsec security-wazuh`** → سرچ `rule.id:100010`
  - 👉 همون alert، ولی **نرمال‌شده به ECS** (source.ip، rule.name، event.module).
- دیتاویو **`sybsec security-suricata`**
  - 👉 alert اسکن شبکه (از مسیر Kafka→Logstash).
- دیتاویو **`sybsec security-anomalies`**
  - 👉 سند ناهنجاری ML با `anomaly_score`، `reason`، `top_features`.

---

## 7️⃣ Caldera — Red Team
**http://167.88.165.161:8888** — `red` / (پسورد توی `docker logs caldera`)

- منوی **agents**
  - 👉 agent `sybsec-endpoint-01` که به Caldera beacon می‌زنه.
- منوی **operations** → operation `apt-foothold` (یا `sybsec-redteam-run`)
  - 👉 ability اجرا شده و **سبز**. بگو: «این حمله رو Caldera زد و Wazuh توی WUI گرفتش (rule 554) — یعنی پوشش تشخیص‌مون کار می‌کنه.»

---

## 🎤 جمله‌ی پایانی برای ارائه
> «یه مهاجم واحد — از اسکن شبکه تا exfil — هم‌زمان توسط ۴ موتور مستقل دیده شد (قانون، ML، شبکه، هوش تهدید)، خودکار با اولویت CRITICAL غنی شد، در عرض چند ثانیه بلاک شد و پرونده‌ش باز شد، و red-team هم تأیید کرد که تشخیص‌ها واقعاً کار می‌کنن. این یعنی **sensor → detect → enrich → respond → case → validate** — کاملاً خودکار و open-source.»

## ترتیب پیشنهادی نمایش (۵ دقیقه)
1. `./scripts/scenario-apt.sh` بزن (خروجی ترمینال خودش روایت می‌کنه)
2. **Wazuh WUI** → brute force + MISP CRITICAL + FIM + MITRE
3. **Shuffle** → اجرای ۴ نودی سبز
4. **TheHive** → پرونده‌ی [SOAR] خودکار
5. **Grafana** → نمودار anomaly و alertها
6. **Caldera** → تأیید red-team
