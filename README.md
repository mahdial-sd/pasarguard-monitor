# 🛡️ PasarGuard Monitor

> سیستم مانیتورینگ و مدیریت هوشمند کاربران Marzban/Marzneshin

[![GitHub stars](https://img.shields.io/github/stars/mahdial-sd/pasarguard-monitor?style=social)](https://github.com/mahdial-sd/pasarguard-monitor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org)

---

## 🌟 ویژگی‌ها

- ✅ **مانیتورینگ چند IP**: شناسایی و غیرفعال‌سازی خودکار کاربران
- ✅ **هشدار مصرف حجم**: اطلاع‌رسانی در ۹۰٪ مصرف ترافیک
- ✅ **هشدار انقضای تاریخ**: پیام خودکار در ۹۰٪ اتمام زمان اشتراک
- ✅ **مدیریت لیمیت شخصی**: تعیین محدودیت IP برای هر کاربر
- ✅ **سیستم Whitelist**: معاف‌سازی کاربران خاص از محدودیت‌ها
- ✅ **ساب ادمین**: ایجاد ادمین‌های فرعی با دسترسی محدود
- ✅ **گزارش‌های دوره‌ای**: آمار و ارسال خودکار وضعیت سیستم
- ✅ **بازگردانی خودکار**: فعال‌سازی مجدد کاربران بلاک شده

---

## 📦 نصب سریع

یک دستور کافیست:
bash <(curl -Ls https://raw.githubusercontent.com/mahdial-sd/pasarguard-monitor/main/install.sh)


---

## 🔧 نصب دستی

### پیش‌نیازها
- سرور لینوکس (Ubuntu 20.04+ یا Debian 11+)
- دسترسی Root
- پنل Marzban یا Marzneshin
- Go 1.21+

### مراحل

git clone https://github.com/mahdial-sd/pasarguard-monitor.git
cd pasarguard-monitor
go build -o pasarguard-monitor main.go
./pasarguard-monitor

---

## 🤖 دستورات ربات

### دستورات عمومی
- `/start` - شروع و راهنما
- `/stats` - آمار کلی سیستم
- `/help` - راهنمای کامل

### مدیریت کاربران
- `/user <username>` - جستجوی کاربر
- `/block <username>` - بلاک دستی
- `/unblock <username>` - رفع بلاک

### تنظیمات لیمیت
- `/setlimit <عدد>` - تنظیم لیمیت پیش‌فرض
- `/userlimit set <user> <limit>` - لیمیت شخصی
- `/userlimit list` - لیست لیمیت‌ها

### Whitelist
- `/whitelist add <user>` - افزودن به لیست سفید
- `/whitelist remove <user>` - حذف از لیست
- `/whitelist list` - نمایش لیست

---

## 📊 گزارش‌های خودکار

- **هر ۲۰ دقیقه**: گزارش کاربران چند IP
- **هر ۱۰ دقیقه**: چک تخلفات و بلاک خودکار
- **هر ۳۰ دقیقه**: هشدار حجم و تاریخ انقضا

---

## 🔄 مدیریت سرویس

وضعیت
systemctl status pasarguard-monitor

لاگ زنده
journalctl -u pasarguard-monitor -f

ری‌استارت
systemctl restart pasarguard-monitor

---

## ⚙️ پیکربندی

فایل `config.yaml`:

panel_url: https://your-panel.com:2087
username: admin
password: your_password
telegram_bot_token: YOUR_BOT_TOKEN
telegram_chat_id: YOUR_CHAT_ID
ip_limit: 2
restore_minutes: 1440
---

## ⭐ حمایت

اگه این پروژه برات مفید بود، یه ستاره ⭐ بده!

**ساخته شده با ❤️ برای جامعه ایرانی**

---

## 📞 پشتیبانی

- **GitHub Issues**: [گزارش باگ](https://github.com/mahdial-sd/pasarguard-monitor/issues)
- **لایسنس**: MIT

