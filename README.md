# PasarGuard Monitor

🚀 سیستم مانیتورینگ و مدیریت هوشمند کاربران Marzban/Marzneshin

## امکانات

✅ مانیتور چند IP و غیرفعال‌سازی خودکار  
✅ هشدار مصرف حجم (90%)  
✅ هشدار انقضای تاریخ (90%)  
✅ مدیریت لیمیت شخصی برای هر کاربر  
✅ سیستم Whitelist  
✅ ساب ادمین با دسترسی محدود  
✅ گزارش‌های دوره‌ای  

## نصب

\`\`\`bash
# کلون کردن پروژه
git clone https://github.com/YourUsername/pasarguard-monitor.git
cd pasarguard-monitor

# نصب Go (اگه نداری)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Build
go build -o pasarguard-monitor main.go
\`\`\`

## تنظیمات

فایل \`config.yaml\` رو ویرایش کن:

\`\`\`yaml
panel_url: https://your-panel.com:port
username: your_admin_username
telegram_bot_token: YOUR_BOT_TOKEN
telegram_chat_id: YOUR_CHAT_ID
\`\`\`

## اجرا

\`\`\`bash
# دستی
./pasarguard-monitor

# با systemd
sudo systemctl enable pasarguard-monitor
sudo systemctl start pasarguard-monitor
\`\`\`

## دستورات ربات

- \`/stats\` - آمار کلی
- \`/user username\` - جستجوی کاربر
- \`/setlimit 5\` - تنظیم لیمیت پیشفرض
- \`/userlimit set user 3\` - لیمیت شخصی
- \`/whitelist add user\` - استثنا
