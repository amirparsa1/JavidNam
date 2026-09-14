<div dir="rtl">

# 📦 راهنمای استقرار جاویدنام

## توکن کلودفلر (برای بات)

> ⚡ **راه سریع / Quick way:** این لینک صفحه‌ی ساخت توکن را با تمام دسترسی‌ها از قبل تنظیم‌شده باز می‌کند — فقط `Continue to summary` → `Create Token`:
>
> [🔑 دریافت توکن اختصاصی جاویدنام](https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=JavidNam%20Panel)
>
> (این همان دکمه‌ای است که بات تلگرام هم می‌دهد. اگر صفحه خالی باز شد، اول در dash.cloudflare.com لاگین کن.)


1. به [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) برو
2. **Create Token** → **Get started** روی «Custom token»
3. دسترسی‌ها:
   - `Account · Workers Scripts : Edit`
   - `Account · D1 : Edit`
   - `Account · Account Settings : Read`
4. Continue → Create Token → کپی کن و برای بات بفرست

> توکن فقط روی اکانت خودت دسترسی دارد، رمزنگاری‌شده ذخیره می‌شود و پیامش حذف می‌گردد.

## استقرار دستی پنل

### ۱) ساخت Worker

1. داشبورد کلودفلر → **Workers & Pages** → **Create** → **Create Worker**
2. نام دلخواه (مثلاً `javidnam`) → **Deploy** → بعد **Edit code**
3. کل محتوای فایل `panel/javidnam-worker.js` را جای‌گذاری کن → **Deploy**

### ۲) ساخت دیتابیس D1

1. منوی **Storage & Databases** → **D1 SQL Database** → **Create**
2. نام: `javidnam-db` → Create
3. در تنظیمات ورکر → **Bindings** → **Add** → نوع `D1`:
   - Variable name: `DB`  (دقیقاً همین)
   - D1 database: دیتابیس ساخته‌شده

> جدول‌ها در اولین اجرا خودکار ساخته می‌شوند؛ نیازی به اجرای SQL نیست.

### ۳) متغیرهای امنیتی

در تنظیمات ورکر → **Settings** → **Variables and Secrets** → **Add (Secret)**:

| نام | مقدار |
|---|---|
| `ADMIN_PASS_HASH` | خروجی فرمول زیر |
| `SESSION_SECRET` | یک رشته‌ی تصادفی طولانی (مثلاً ۶۴ کاراکتر) |

برای ساخت `ADMIN_PASS_HASH` (فرمت `salt$hash`):

```bash
# در لینوکس/مک:
SALT=$(openssl rand -hex 8)
PASS="رمز-مدیریت-تو"
HASH=$(printf '%s' "$SALT:$PASS" | sha256sum | cut -d' ' -f1)
echo "ADMIN_PASS_HASH=$SALT\$$HASH"
```

یا با Node:

```bash
node -e "const c=require('crypto');const s=c.randomBytes(8).toString('hex');const p='رمز-مدیریت-تو';console.log(s+'\$'+c.createHash('sha256').update(s+':'+p).digest('hex'))"
```

> اگر این متغیرها را تنظیم نکنی، پنل در اولین بازدید حالت «نصب اولیه» نشان می‌دهد و از تو رمز می‌گیرد (برای اکانت شخصی قابل قبول است؛ برای استفاده‌ی عمومی حتماً از متغیرها استفاده کن).

### ۴) ورود

- آدرس ورکر: `https://<name>.<subdomain>.workers.dev`
- با رمز مدیریت وارد شو → کاربر بساز → لینک ساب `/sub/<token>` را بده.

## تنظیم لوکیشن‌ها و Clean IP

در پنل → تنظیمات → لوکیشن‌ها می‌توانی برای هر کانفیگ میزبان جدا بگذاری:
- دامنه‌ی ورکر خودت (پیش‌فرض)
- هر دامنه/زیردامنه‌ی دیگری که به کلودفلر پروکسی‌شده وصل است (CDN)
- آی‌پی‌های «تمیز» کلودفلر + SNI مناسب

پورت‌های مجاز TLS روی کلودفلر: `443, 2053, 2083, 2087, 2096, 8443`

## استقرار بات دیپلوی (اختیاری — برای اجرای عمومی)

اگر بخواهی بات را خودت اجرا کنی:

```bash
# پیش‌نیاز: Node 18+
cd bot
# با wrangler:
npx wrangler deploy
```

متغیرهای لازم را در `wrangler.toml` نمونه ببینید:
- `TELEGRAM_TOKEN` (secret)
- `BOT_KEY` (secret — کلید رمزنگاری + webhook secret)
- `OWNER_CODE` (secret — کد مالکیت بات)
- `PATH_TOKEN` (مسیر وب‌هوک)
- `PANEL_SOURCE_URL` (آدرس سورس پنل روی گیت‌هاب)
- بایندینگ KV با نام `BOT_KV`

سپس وب‌هوک را ست کن:

```bash
curl "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -d "url=https://<bot>.workers.dev/<PATH_TOKEN>" \
  -d "secret_token=<BOT_KEY>"
```

## دریافت آپدیت

- اگر با بات نصب کرده‌ای: پنل‌های من → 🔄 آپدیت پنل
- اگر دستی نصب کرده‌ای: فایل جدید `javidnam-worker.js` را جای‌گذاری کن و Deploy کن — داده‌ها در D1 می‌مانند.

</div>
