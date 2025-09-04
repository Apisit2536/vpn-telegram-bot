# 🚀 Telegram VPN Bot (Xray/XUI Manager)

این پروژه یک **ربات تلگرام** است که به شما امکان مدیریت کامل اکانت‌های VPN (مبتنی بر **Xray/XUI**) را می‌دهد.  
کاربران می‌توانند از طریق این ربات:
- خرید اشتراک انجام دهند
- فیش واریزی ارسال کنند
- سرویس‌های فعال خود را مشاهده و تمدید کنند
- هشدار کاهش حجم یا نزدیک شدن به تاریخ انقضا دریافت کنند
- راهنمای نصب اپلیکیشن و لینک‌های دانلود کلاینت‌ها را ببینند
- با پشتیبانی در ارتباط باشند

ادمین هم می‌تواند:
- اکانت‌ها را به کاربران لینک کند یا حذف کند
- پیام پشتیبانی را پاسخ دهد
- هشدارهای مربوط به استفاده غیرمجاز (تعداد IP بیش از حد مجاز) دریافت کند
- به کاربران لینک اتصال ارسال کند

---

## ✨ ویژگی‌ها (Features)

### برای کاربران
- ✅ بررسی خودکار عضویت در کانال قبل از استفاده  
- ✅ خرید اکانت (یک‌کاربره و دوکاربره با حجم‌های مختلف)  
- ✅ ارسال فیش واریزی به ادمین  
- ✅ مشاهده گزارش اکانت (حجم مصرفی، باقی‌مانده، تاریخ انقضا، وضعیت فعال/غیرفعال)  
- ✅ دریافت هشدار:
  - حجم کمتر از `1GB`
  - کمتر از `3 روز` تا انقضا  
- ✅ دسترسی سریع به لینک دانلود اپلیکیشن‌ها (iOS, Android, Windows, MacOS)  
- ✅ امکان برقراری ارتباط مستقیم با پشتیبانی  

### برای ادمین
- 👤 مشاهده اعلان فعال شدن کاربران  
- 🔗 لینک‌کردن اکانت به کاربر و تعیین محدودیت آی‌پی  
- ❌ حذف سرویس از کاربر  
- 📨 دریافت پیام پشتیبانی و پاسخ‌دهی  
- ⚠️ هشدار اتصال بیش از حد مجاز (بیشتر از IP تعیین‌شده)  
- 📡 ارسال مستقیم لینک اتصال به کاربر  

---

## 🛠️ تکنولوژی‌های استفاده‌شده
- [Python](https://www.python.org/)  
- [python-telegram-bot v20+](https://docs.python-telegram-bot.org/)  
- [SQLite3](https://www.sqlite.org/) (برای مدیریت دیتابیس کاربران)  
- [dotenv](https://pypi.org/project/python-dotenv/) (برای مدیریت متغیرهای محیطی)  

---

## 📂 ساختار پروژه
```
├── bot.py              # منطق اصلی ربات و هندلرها
├── db.py               # مدیریت دیتابیس کاربران و اشتراک‌ها
├── bot_users.db        # دیتابیس SQLite (بعد از اولین اجرا ساخته می‌شود)
├── .env                # تنظیمات و کلیدها (توکن ربات، آی‌دی ادمین، مسیر لاگ و دیتابیس)
├── requirements.txt    # لایبرری هاب لازم برای اجرای سورس
```

---

## ⚙️ راه‌اندازی (Setup)

### 1️⃣ نصب پیش‌نیازها
```bash
git clone https://github.com/majid-abedi/vpn-telegram-bot.git
cd vpn-telegram-bot
pip install -r requirements.txt
```

### 2️⃣ ایجاد فایل `.env`
یک فایل به نام `.env` در ریشه پروژه بسازید:
```env
BOT_TOKEN=توکن_ربات_تلگرام
ADMIN_CHAT_ID=آی‌دی‌ـچت‌ـ‌ادمین
XRAY_ACCESS_LOG=آدرس‌ـ‌لاگ
XUI_DB_PATH=آدرس‌ـ‌دیتابیس
CARD_INFO=xxxx-xxxx-xxxx-xxxx
CHANNEL_USERNAME=یوزر‌ـ‌کانال‌ـ‌تلگرام
```

### 3️⃣ اجرای ربات
```bash
python bot.py
```

---

## 🧑‍💻 دستورات ادمین
- `/link <telegram_id> <email> <allow_ip>` → لینک کردن اکانت به کاربر  
- `/unlink <telegram_id> <email>` → حذف اکانت کاربر  
- `/reply <telegram_id> <message>` → پاسخ به پیام پشتیبانی  
- `/connection <telegram_id> <link>` → ارسال لینک اتصال به کاربر  

---


## 🌐 English Summary

**Telegram VPN Bot** is a management bot for **Xray/XUI VPN services**.  
It allows users to purchase, renew, and manage subscriptions directly inside Telegram, while admins can monitor usage, link accounts, and get alerts for abnormal activities.

🔑 Key Features:
- User subscription management  
- Automated expiry & quota alerts  
- Channel membership check  
- Payment receipt verification  
- Admin tools for linking/unlinking accounts and sending connection details  

---

## 📜 License
MIT License – feel free to use, modify, and share.

---

## 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## ⭐ حمایت
اگر این پروژه براتون مفید بود، خوشحال می‌شم یک ⭐ به ریپازیتوری بدید.
