package main

import (
    "bufio"
    "io"
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "regexp"
    "strings"
    "sync"
    "time"
    "os"

    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
    "gopkg.in/yaml.v3"
)

type Config struct {
    PanelURL         string   `yaml:"panel_url"`
    Username         string   `yaml:"username"`
    Password         string   `yaml:"password"`
    TelegramBotToken string   `yaml:"telegram_bot_token"`
    TelegramChatID   int64    `yaml:"telegram_chat_id"`
    SubAdmins        []int64  `yaml:"sub_admins"`
    SendInterval     int      `yaml:"send_interval"`
    EnableBlocked    bool     `yaml:"enable_blocked"`
    EnableRejected   bool     `yaml:"enable_rejected"`
    EnableConnected  bool     `yaml:"enable_connected"`
    IPLimit          int      `yaml:"ip_limit"`
    RestoreMinutes   int      `yaml:"restore_minutes"`
    Whitelist        []string `yaml:"whitelist"`

}

type UserLimits struct {
    DefaultLimit int            `json:"default_limit"`
    Users        map[string]int `json:"users"`
}

type UserDetail struct {
    Username    string `json:"username"`
    Status      string `json:"status"`
    UsedTraffic int64  `json:"used_traffic"`
    DataLimit   int64  `json:"data_limit"`
    Expire      string `json:"expire"`
    OnlineAt    string `json:"online_at"`
    Admin        string `json:"admin"`
}

type Node struct {
    ID   int    `json:"id"`
    Name string `json:"name"`
}

type LogEvent struct {
    Timestamp string
    Username  string
    IP        string
    NodeName  string
    EventType string
}

type ActiveIP struct {
    Username string
    IP       string
    NodeName string
    LastSeen time.Time
}

type Stats struct {
    BlockedToday   int
    RejectedToday  int
    ConnectedToday int
    LastReset      time.Time
}

type ViolationRecord struct {
    Username       string
    ViolationCount int
    LastViolation  time.Time
    DisabledAt     *time.Time
}

type DataUsageWarning struct {
    Username    string
    WarnedAt    time.Time
}

var (
    dataWarnings      map[string]*DataUsageWarning
    dataWarningsMutex sync.Mutex
)

type ExpiryWarning struct {
    Username string
    WarnedAt time.Time
}

var (
    expiryWarnings      map[string]*ExpiryWarning
    expiryWarningsMutex sync.Mutex
)

var (
    violations      map[string]*ViolationRecord
    violationsMutex sync.Mutex
)

var (
    config      Config
    userLimits  UserLimits
    bot         *tgbotapi.BotAPI
    authToken   string
    httpClient  *http.Client
    logPattern  *regexp.Regexp
    
    blockedEvents   []LogEvent
    rejectedEvents  []LogEvent
    connectedEvents []LogEvent
    eventMutex      sync.Mutex
    
    activeIPs      map[string]*ActiveIP
    activeIPsMutex sync.RWMutex
    
    dailyStats Stats
    statsMutex sync.Mutex
    limiter    *RateLimiter
)

// Input validation functions
func validateUsername(username string) error {
    if len(username) > 50 {
        return fmt.Errorf("username too long")
    }
    if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username); !matched {
        return fmt.Errorf("invalid characters")
    }
    return nil
}

func validateLimit(limit int) error {
    if limit < 1 || limit > 999 {
        return fmt.Errorf("limit must be 1-999")
    }
    return nil
}

// Rate limiter
type RateLimiter struct {
    requests map[int64][]time.Time
    mu       sync.Mutex
}

func NewRateLimiter() *RateLimiter {
    return &RateLimiter{
        requests: make(map[int64][]time.Time),
    }
}

func (rl *RateLimiter) Allow(userID int64) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    now := time.Now()
    windowStart := now.Add(-1 * time.Minute)
    
    var validRequests []time.Time
    for _, t := range rl.requests[userID] {
        if t.After(windowStart) {
            validRequests = append(validRequests, t)
        }
    }
    
    if len(validRequests) >= 10 {
        return false
    }
    
    rl.requests[userID] = append(validRequests, now)
    return true
}

func main() {
    log.SetFlags(log.LstdFlags)
    log.Println("🚀 PasarGuard Monitor Starting...")

    if err := loadConfig("config.yaml"); err != nil {
        log.Fatalf("❌ Failed to load config: %v", err)
    }


    // بعد از خط 122
if envPass := os.Getenv("PANEL_PASSWORD"); envPass != "" {
    config.Password = envPass
    log.Println("✅ Using password from environment")
}

    // Load user limits
    limitsData, err := ioutil.ReadFile("user-limits.json")
    if err != nil {
        log.Println("⚠️ user-limits.json not found, using default limit for all users")
        userLimits = UserLimits{
            DefaultLimit: config.IPLimit,
            Users:        make(map[string]int),
        }
    } else {
        if err := json.Unmarshal(limitsData, &userLimits); err != nil {
            log.Printf("❌ Failed to parse user-limits.json: %v", err)
            userLimits = UserLimits{
                DefaultLimit: config.IPLimit,
                Users:        make(map[string]int),
            }
        } else {
            log.Printf("✅ Loaded user limits: default=%d, custom=%d users", 
                userLimits.DefaultLimit, len(userLimits.Users))
        }
    }

    httpClient = &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
        },
        Timeout: 30 * time.Second,
    }
    
    logPattern = regexp.MustCompile(`^data: ([^ ]+\s+[^ ]+) from ([\d.]+):\d+ (\w+) .*email: (.+)$`)
    activeIPs = make(map[string]*ActiveIP)
    violations = make(map[string]*ViolationRecord)
    dataWarnings = make(map[string]*DataUsageWarning)
    expiryWarnings = make(map[string]*ExpiryWarning)
    dailyStats = Stats{LastReset: time.Now()}

    var botErr error
    bot, botErr = tgbotapi.NewBotAPI(config.TelegramBotToken)
    limiter = NewRateLimiter()  
    if botErr != nil {
        log.Fatalf("❌ Failed to connect to Telegram: %v", botErr)
    }
    log.Printf("✅ Connected to Telegram as @%s", bot.Self.UserName)

    if err := login(); err != nil {
        log.Fatalf("❌ Login failed: %v", err)
    }
    log.Println("✅ Logged in successfully")

    nodes, err := getNodes()
    if err != nil {
        log.Fatalf("❌ Failed to get nodes: %v", err)
    }
    log.Printf("✅ Found %d nodes", len(nodes))

    sendMessage("🟢 سرویس مانیتور پاسارگاد راه‌اندازی شد\n\nدستورات:\n/stats - آمار\n/user <username> - جستجو\n/help - راهنما")

    go handleTelegramCommands()
    go sendPeriodicUpdates()
    go cleanupOldIPs()
    go sendDailyStats()
    go sendActiveUsersReport()
    go autoDisableViolators()
    go autoRestoreUsers()
    go checkDataUsageWarnings()

    var wg sync.WaitGroup
    for _, node := range nodes {
        wg.Add(1)
        go func(n Node) {
            defer wg.Done()
            streamNodeLogs(n)
        }(node)
    }

    wg.Wait()
}

func loadConfig(filename string) error {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return err
    }
    return yaml.Unmarshal(data, &config)
}

func login() error {
    loginData := fmt.Sprintf("username=%s&password=%s", config.Username, config.Password)
    resp, err := httpClient.Post(
        config.PanelURL+"/api/admin/token",
        "application/x-www-form-urlencoded",
        bytes.NewBuffer([]byte(loginData)),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return err
    }

    authToken = result["access_token"].(string)
    return nil
}

func getNodes() ([]Node, error) {
    req, _ := http.NewRequest("GET", config.PanelURL+"/api/nodes", nil)
    req.Header.Set("Authorization", "Bearer "+authToken)

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        Nodes []Node `json:"nodes"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return result.Nodes, nil
}

func getAllUsers() ([]UserDetail, error) {
    req, _ := http.NewRequest("GET", config.PanelURL+"/api/users?limit=10000", nil)
    req.Header.Set("Authorization", "Bearer "+authToken)
    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        Users []UserDetail `json:"users"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return result.Users, nil
}

func streamNodeLogs(node Node) {
    log.Printf("📂 Monitoring node: %s (ID: %d)", node.Name, node.ID)
    
    retryCount := 0
    maxRetries := 3

    for {
        func() {
            defer func() {
                if r := recover(); r != nil {
                    log.Printf("⚠️ Recovered panic in %s: %v", node.Name, r)
                }
            }()
            
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
            defer cancel()
            
            req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/node/%d/logs", config.PanelURL, node.ID), nil)
            req.Header.Set("Authorization", "Bearer "+authToken)

            resp, err := httpClient.Do(req)
            if err != nil {
                retryCount++
                if retryCount >= maxRetries {
                    log.Printf("❌ Node %s failed after %d retries. Waiting 30s...", node.Name, maxRetries)
                    time.Sleep(30 * time.Second)
                    retryCount = 0
                } else {
                    log.Printf("❌ Error connecting to %s (attempt %d/%d): %v", node.Name, retryCount, maxRetries, err)
                    time.Sleep(10 * time.Second)
                }
                return
            }
            defer resp.Body.Close()
            
            retryCount = 0

            scanner := bufio.NewScanner(resp.Body)
            scanner.Buffer(make([]byte, 64*1024), 1024*1024)
            
            for scanner.Scan() {
                select {
                case <-ctx.Done():
                    return
                default:
                    line := scanner.Text()
                    if line != "" {
                        processLogLine(line, node.Name)
                    }
                }
            }

            if err := scanner.Err(); err != nil {
                log.Printf("❌ Error reading logs for %s: %v. Retrying in 10s...", node.Name, err)
                time.Sleep(10 * time.Second)
            }
        }()
    }
}

func processLogLine(line, nodeName string) {
    match := logPattern.FindStringSubmatch(line)
    if len(match) < 5 {
        return
    }

    timestamp := match[1]
    ip := match[2]
    eventType := match[3]
    rawEmail := match[4]
    
    username := rawEmail
    if strings.Contains(rawEmail, ".") {
        parts := strings.Split(rawEmail, ".")
        if len(parts) > 1 {
            username = parts[1]
        }
    }

    event := LogEvent{
        Timestamp: timestamp,
        Username:  username,
        IP:        ip,
        NodeName:  nodeName,
        EventType: eventType,
    }

    if eventType == "accepted" {
        trackActiveIP(username, ip, nodeName)
    }

    eventMutex.Lock()
    defer eventMutex.Unlock()

    if eventType == "rejected" && config.EnableRejected {
        rejectedEvents = append(rejectedEvents, event)
        updateStats("rejected")
    } else if eventType == "accepted" && config.EnableConnected {
        connectedEvents = append(connectedEvents, event)
        updateStats("connected")
    } else if eventType != "accepted" && eventType != "rejected" && config.EnableBlocked {
        blockedEvents = append(blockedEvents, event)
        updateStats("blocked")
    }
}

func trackActiveIP(username, ip, nodeName string) {
    activeIPsMutex.Lock()
    defer activeIPsMutex.Unlock()
    
    key := username + "-" + ip
    activeIPs[key] = &ActiveIP{
        Username: username,
        IP:       ip,
        NodeName: nodeName,
        LastSeen: time.Now(),
    }
}

func cleanupOldIPs() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        activeIPsMutex.Lock()
        now := time.Now()
        for key, active := range activeIPs {
            if now.Sub(active.LastSeen) > 60*time.Second {
                delete(activeIPs, key)
            }
        }
        activeIPsMutex.Unlock()
    }
}

func updateStats(eventType string) {
    statsMutex.Lock()
    defer statsMutex.Unlock()
    
    if time.Since(dailyStats.LastReset) > 24*time.Hour {
        dailyStats = Stats{LastReset: time.Now()}
    }
    
    switch eventType {
    case "blocked":
        dailyStats.BlockedToday++
    case "rejected":
        dailyStats.RejectedToday++
    case "connected":
        dailyStats.ConnectedToday++
    }
}

func sendPeriodicUpdates() {
    ticker := time.NewTicker(time.Duration(config.SendInterval) * time.Second)
    for range ticker.C {
        sendTelegramUpdates()
    }
}

func sendTelegramUpdates() {
    eventMutex.Lock()
    blocked := blockedEvents
    rejected := rejectedEvents
    connected := connectedEvents
    blockedEvents = nil
    rejectedEvents = nil
    connectedEvents = nil
    eventMutex.Unlock()

    if len(blocked) == 0 && len(rejected) == 0 && len(connected) == 0 {
        return
    }

    var message strings.Builder

    if len(blocked) > 0 {
        message.WriteString("🚫 کاربران بلاک شده:\n")
        seen := make(map[string]bool)
        for _, event := range blocked {
            key := event.Username + "-" + event.IP
            if !seen[key] {
                seen[key] = true
                
                details := getUserDetails(event.Username)
                message.WriteString(fmt.Sprintf("نود %s:\n", event.NodeName))
                message.WriteString(fmt.Sprintf("  • %s - IP: %s\n", event.Username, event.IP))
                if details != "" {
                    message.WriteString(fmt.Sprintf("    %s\n", details))
                }
            }
        }
        message.WriteString("\n")
    }

    if len(rejected) > 0 {
        message.WriteString("❌ اتصالات رد شده:\n")
        seen := make(map[string]bool)
        for _, event := range rejected {
            key := event.Username + "-" + event.IP
            if !seen[key] {
                seen[key] = true
                message.WriteString(fmt.Sprintf("نود %s:\n", event.NodeName))
                message.WriteString(fmt.Sprintf("  • %s - IP: %s\n", event.Username, event.IP))
            }
        }
        message.WriteString("\n")
    }

    if len(connected) > 0 {
        message.WriteString("🟢 اتصالات جدید:\n")
        seen := make(map[string]bool)
        nodeGroups := make(map[string][]LogEvent)
        
        for _, event := range connected {
            key := event.Username + "-" + event.IP
            if !seen[key] {
                seen[key] = true
                nodeGroups[event.NodeName] = append(nodeGroups[event.NodeName], event)
            }
        }
        
        for nodeName, events := range nodeGroups {
            message.WriteString(fmt.Sprintf("نود %s:\n", nodeName))
            for _, event := range events {
                message.WriteString(fmt.Sprintf("  • %s - IP: %s\n", event.Username, event.IP))
            }
        }
    }

    if message.Len() > 0 {
        sendMessage(message.String())
    }
}

func getUserDetails(username string) string {
    req, _ := http.NewRequest("GET", config.PanelURL+"/api/user/"+username, nil)
    req.Header.Set("Authorization", "Bearer "+authToken)

    resp, err := httpClient.Do(req)
    if err != nil {
        return "⚠️ خطا در دریافت اطلاعات"
    }
    defer resp.Body.Close()

    var user UserDetail
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return "⚠️ خطا در parse"
    }

    var details strings.Builder
    
    statusEmoji := "✅"
    if user.Status != "active" {
        statusEmoji = "🔴"
    }
    details.WriteString(fmt.Sprintf("%s %s", statusEmoji, user.Status))
    
    usedGB := float64(user.UsedTraffic) / 1073741824
    limitGB := float64(user.DataLimit) / 1073741824
    percentage := (float64(user.UsedTraffic) / float64(user.DataLimit)) * 100
    details.WriteString(fmt.Sprintf(" | 📊 %.1fGB/%.0fGB (%.0f%%)", usedGB, limitGB, percentage))
    
    if user.Expire != "" {
        expireTime, err := time.Parse(time.RFC3339, user.Expire)
        if err == nil {
            daysLeft := int(time.Until(expireTime).Hours() / 24)
            if daysLeft < 0 {
                details.WriteString(" | ⏰ منقضی شده")
            } else {
                details.WriteString(fmt.Sprintf(" | ⏰ %d روز", daysLeft))
            }
        }
    }

    return details.String()
}

func handleTelegramCommands() {
    u := tgbotapi.NewUpdate(0)
    u.Timeout = 60

    updates := bot.GetUpdatesChan(u)

    for update := range updates {
        if update.Message == nil {
            continue
        }
        chatID := update.Message.Chat.ID

isMainAdmin := chatID == config.TelegramChatID
isSubAdmin := false
for _, id := range config.SubAdmins {
    if id == chatID {
        isSubAdmin = true
        break
    }
}



        command := update.Message.Command()
        args := update.Message.CommandArguments()

        switch command {
case "start", "help":
    if !isMainAdmin && !isSubAdmin {
        sendMessage("❌ شما دسترسی ندارید")
        continue
    }
    if isSubAdmin {
        helpText := `📚 دستورات ادمین فرعی:

👤 مدیریت محدودیت های شخصی:
/userlimit set <username> <limit> - تنظیم لیمیت برای یک کاربر
/userlimit remove <username> - حذف لیمیت شخصی
/userlimit list - نمایش لیست لیمیت های شخصی
/userlimit show <username> - نمایش لیمیت یک کاربر`
        sendMessageTo(chatID, helpText)
    } else {
        helpText := `📚 راهنمای دستورات:

📊 مانیتورینگ:
/stats - آمار کلی سیستم
/user <username> - جستجوی یوزر و IP های فعال
/nodes - وضعیت نودها

⚙️ تنظیمات محدودیت IP:
/settings - نمایش تنظیمات فعلی
/setlimit <عدد> - تغییر حد مجاز IP (پیش‌فرض)
/setrestore <دقیقه> - زمان بازگردانی خودکار

👤 مدیریت محدودیت های شخصی:
/userlimit set <username> <limit> - تنظیم لیمیت برای یک کاربر
/userlimit remove <username> - حذف لیمیت شخصی
/userlimit list - نمایش لیست لیمیت های شخصی
/userlimit show <username> - نمایش لیمیت یک کاربر

📋 مدیریت استثناها:
/whitelist add <username> - افزودن به لیست سفید (نامحدود)
/whitelist remove <username> - حذف از لیست سفید
/whitelist list - نمایش لیست

/help - نمایش این راهنما`
        sendMessageTo(chatID, helpText)
    }

case "stats":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    handleStatsCommand()

case "user":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    if args == "" {
        sendMessage("❌ لطفاً نام کاربری را وارد کنید:\n/user username")
    } else {
        handleUserCommand(args)
    }

case "nodes":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    handleNodesCommand()

case "setlimit":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    if args == "" {
        sendMessage("❌ مثال: /setlimit 5")
    } else {
        handleSetLimit(chatID, args)
    }

case "setrestore":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    if args == "" {
        sendMessage("❌ مثال: /setrestore 90")
    } else {
        handleSetRestore(chatID, args)
    }

case "whitelist":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    handleWhitelist(chatID, args)

    case "userlimit":
    if !isMainAdmin && !isSubAdmin {
        sendMessage("❌ شما دسترسی ندارید")
        continue
    }
      if !limiter.Allow(chatID) {
        sendMessageTo(chatID, "⏳ Too many requests! Wait 1 minute.")
        continue
    }
    log.Printf("🔍 userlimit command from chatID: %d, args: %s", chatID, args)
    parts := strings.Fields(args)
    if len(parts) == 0 {
        handleUserLimit(chatID, args)
        continue
    }
    
    // اگه ساب ادمین بود و میخواد list ببینه، اجازه نده
    isSubAdminCheck := false
    for _, id := range config.SubAdmins {
        if id == chatID {
            isSubAdminCheck = true
            break
        }
    }
    if isSubAdminCheck && parts[0] == "list" {
        sendMessageTo(chatID, "❌ شما اجازه دسترسی به این بخش را ندارید")
        continue
    }
    
    handleUserLimit(chatID, args)
case "settings":
    if !isMainAdmin {
        sendMessage("❌ فقط ادمین اصلی به این دستور دسترسی دارد")
        continue
    }
    handleSettingsCommand(chatID)
}

    }
}

func handleStatsCommand() {
    statsMutex.Lock()
    stats := dailyStats
    statsMutex.Unlock()

    activeIPsMutex.RLock()
    activeCount := len(activeIPs)
    activeIPsMutex.RUnlock()

    message := fmt.Sprintf(`📊 آمار سیستم

🚫 بلاک شده امروز: %d
❌ رد شده امروز: %d
🟢 اتصال جدید امروز: %d
📡 کاربران فعال الان: %d

🕐 ساعت: %s`,
        stats.BlockedToday,
        stats.RejectedToday,
        stats.ConnectedToday,
        activeCount,
        time.Now().Format("15:04:05"),
    )

    sendMessage(message)
}

func handleUserCommand(username string) {
    details := getUserDetails(username)
    
    // چک کن لیمیت کاربر چقدره
    userLimit := getUserLimit(username)
    
    activeIPsMutex.RLock()
    var userIPs []string
    for _, active := range activeIPs {
        if active.Username == username {
            userIPs = append(userIPs, fmt.Sprintf("  • IP: %s | نود: %s | %s پیش",
                active.IP,
                active.NodeName,
                time.Since(active.LastSeen).Round(time.Second),
            ))
        }
    }
    activeIPsMutex.RUnlock()

    var message strings.Builder
    message.WriteString(fmt.Sprintf("👤 کاربر: %s\n", username))
    message.WriteString(fmt.Sprintf("🔢 محدودیت IP: %d\n\n", userLimit))
    
    if details != "" {
        message.WriteString(details + "\n\n")
    }
    
    if len(userIPs) > 0 {
        message.WriteString(fmt.Sprintf("📍 IP های فعال (%d):\n", len(userIPs)))
        for _, ip := range userIPs {
            message.WriteString(ip + "\n")
        }
    } else {
        message.WriteString("⚠️ هیچ IP فعالی یافت نشد")
    }

    sendMessage(message.String())
}

func handleNodesCommand() {
    nodes, err := getNodes()
    if err != nil {
        sendMessage("❌ خطا در دریافت لیست نودها")
        return
    }

    var message strings.Builder
    message.WriteString(fmt.Sprintf("📡 لیست نودها (%d):\n\n", len(nodes)))
    
    for _, node := range nodes {
        message.WriteString(fmt.Sprintf("• %s (ID: %d)\n", node.Name, node.ID))
    }

    sendMessage(message.String())
}

func sendActiveUsersReport() {
    ticker := time.NewTicker(20 * time.Minute)
    for range ticker.C {
        activeIPsMutex.RLock()
        
        userIPs := make(map[string][]string)
        for _, active := range activeIPs {
            userIPs[active.Username] = append(userIPs[active.Username], 
                fmt.Sprintf("%s (نود: %s)", active.IP, active.NodeName))
        }
        activeIPsMutex.RUnlock()
        
        if len(userIPs) == 0 {
            continue
        }

        var message strings.Builder
        message.WriteString(fmt.Sprintf("📊 گزارش کاربران فعال - %s\n\n", 
            time.Now().Format("15:04")))

        multiIPUsers := 0
        for username, ips := range userIPs {
            if len(ips) > 1 {
                multiIPUsers++
                userLimit := getUserLimit(username)
                message.WriteString(fmt.Sprintf("👤 %s (%d/%d IP):\n", username, len(ips), userLimit))
                for _, ip := range ips {
                    message.WriteString(fmt.Sprintf("  • %s\n", ip))
                }
                message.WriteString("\n")
            }
        }

        if multiIPUsers == 0 {
            message.WriteString("✅ همه کاربران تک IP هستند")
        } else {
            message.WriteString(fmt.Sprintf("⚠️ تعداد کاربران چند IP: %d", multiIPUsers))
        }

        sendMessage(message.String())
    }
}

func autoDisableViolators() {
    ticker := time.NewTicker(10 * time.Minute)
    for range ticker.C {
        activeIPsMutex.RLock()
        userIPCount := make(map[string]int)
        for _, active := range activeIPs {
            userIPCount[active.Username]++
        }
        activeIPsMutex.RUnlock()
        
        violationsMutex.Lock()
        for username, count := range userIPCount {
            if isWhitelisted(username) {
                continue
            }
            
            userLimit := getUserLimit(username)
            
            if count > userLimit {
                if violations[username] == nil {
                    violations[username] = &ViolationRecord{
                        Username: username,
                    }
                }
                
                rec := violations[username]
                
                if rec.DisabledAt != nil {
                    continue
                }
                
                if time.Since(rec.LastViolation) > 10*time.Minute {
                    rec.ViolationCount = 1
                } else {
                    rec.ViolationCount++
                }
                rec.LastViolation = time.Now()
                
                log.Printf("⚠️ %s has %d IPs (limit: %d, violation %d/3)", username, count, userLimit, rec.ViolationCount)
                
                if rec.ViolationCount >= 3 {
                    if disableUser(username) {
                        now := time.Now()
                        rec.DisabledAt = &now
                        msg := fmt.Sprintf("🚫 کاربر %s به دلیل %d IP فعال غیرفعال شد (حد مجاز: %d)\n⏰ روشن می‌شود: %d دقیقه دیگر",
                            username, count, userLimit, config.RestoreMinutes)
                        sendMessage(msg)
                        log.Printf("🚫 Disabled user: %s (%d IPs, limit: %d)", username, count, userLimit)
                    }
                }
            }
        }
        violationsMutex.Unlock()
    }
}

func autoRestoreUsers() {
    ticker := time.NewTicker(1 * time.Minute)
    for range ticker.C {
        violationsMutex.Lock()
        for username, rec := range violations {
            if rec.DisabledAt != nil {
                if time.Since(*rec.DisabledAt) >= time.Duration(config.RestoreMinutes)*time.Minute {
                    if enableUser(username) {
                        msg := fmt.Sprintf("✅ کاربر %s دوباره فعال شد", username)
                        sendMessage(msg)
                        log.Printf("✅ Re-enabled user: %s", username)
                        delete(violations, username)
                    }
                }
            }
        }
        violationsMutex.Unlock()
    }
}

func checkDataUsageWarnings() {
    ticker := time.NewTicker(30 * time.Minute)
    for range ticker.C {
        // لیست تمام کاربران رو بگیر
        users, err := getAllUsers()
        if err != nil {
            log.Printf("❌ Error getting users for data check: %v", err)
            continue
        }

        dataWarningsMutex.Lock()
        for _, user := range users {
            // اگه قبلاً هشدار داده شده، رد کن
            if warn, exists := dataWarnings[user.Username]; exists {
                // اگه بیشتر از 24 ساعت گذشته، ریست کن
                if time.Since(warn.WarnedAt) < 24*time.Hour {
                    continue
                }
            }

            if user.DataLimit == 0 {
                continue // نامحدود
            }

            percentage := (float64(user.UsedTraffic) / float64(user.DataLimit)) * 100

            if percentage >= 90 {
                usedGB := float64(user.UsedTraffic) / 1073741824
                limitGB := float64(user.DataLimit) / 1073741824
                remainingGB := (float64(user.DataLimit) - float64(user.UsedTraffic)) / 1073741824

                adminName := user.Admin
                if adminName == "" {
                    adminName = "نامشخص"
                }

                msg := fmt.Sprintf(`⚠️ هشدار حجم

👤 کاربر: %s
👔 ادمین: %s

📊 حجم کل: %.1f GB
🔴 مصرف شده: %.1f GB (%.0f%%)
💾 باقی‌مانده: %.1f GB`,
                    user.Username,
                    adminName,
                    limitGB,
                    usedGB,
                    percentage,
                    remainingGB,
                )

                sendMessage(msg)
                log.Printf("⚠️ Data warning sent for %s (%.0f%%)", user.Username, percentage)

                // ثبت که هشدار داده شده
                dataWarnings[user.Username] = &DataUsageWarning{
                    Username: user.Username,
                    WarnedAt: time.Now(),
                }
            }
        }
                // چک هشدار تاریخ انقضا
        expiryWarningsMutex.Lock()
        for _, user := range users {
            // اگه قبلاً هشدار داده شده، رد کن
            if warn, exists := expiryWarnings[user.Username]; exists {
                if time.Since(warn.WarnedAt) < 24*time.Hour {
                    continue
                }
            }

            if user.Expire == "" {
                continue // بدون تاریخ انقضا
            }

            expireTime, err := time.Parse(time.RFC3339, user.Expire)
            if err != nil {
                continue
            }

            now := time.Now()
            if expireTime.Before(now) {
                continue // منقضی شده، نیازی به هشدار نیست
            }

            // محاسبه روزهای باقی‌مانده
            daysRemaining := int(time.Until(expireTime).Hours() / 24)

            // محاسبه کل مدت (فرض: از OnlineAt یا 30 روز پیش)
            var createdTime time.Time
            if user.OnlineAt != "" {
                createdTime, err = time.Parse(time.RFC3339, user.OnlineAt)
                if err != nil {
                    createdTime = expireTime.AddDate(0, 0, -30) // فرض: 30 روز پیش
                }
            } else {
                createdTime = expireTime.AddDate(0, 0, -30) // فرض: 30 روز پیش
            }

            totalDays := int(expireTime.Sub(createdTime).Hours() / 24)
            if totalDays <= 0 {
                continue
            }

            daysPassed := int(now.Sub(createdTime).Hours() / 24)
            percentPassed := (float64(daysPassed) / float64(totalDays)) * 100

            // اگه بیشتر از 90% گذشته (کمتر از 10% باقی مونده)
            if percentPassed >= 90 {
                adminName := user.Admin
                if adminName == "" {
                    adminName = "نامشخص"
                }

                msg := fmt.Sprintf(`⏰ هشدار انقضا

👤 کاربر: %s
👔 ادمین: %s

📅 تاریخ ایجاد: %s
🔴 تاریخ انقضا: %s
⏱️ مدت کل: %d روز
📊 گذشته: %d روز (%.0f%%)
💚 باقی‌مانده: %d روز`,
                    user.Username,
                    adminName,
                    createdTime.Format("2006-01-02"),
                    expireTime.Format("2006-01-02"),
                    totalDays,
                    daysPassed,
                    percentPassed,
                    daysRemaining,
                )

                sendMessage(msg)
                log.Printf("⏰ Expiry warning sent for %s (%d days left)", user.Username, daysRemaining)

                expiryWarnings[user.Username] = &ExpiryWarning{
                    Username: user.Username,
                    WarnedAt: time.Now(),
                }
            }
        }
        expiryWarningsMutex.Unlock()
    }
}

func getUserLimit(username string) int {
    if limit, exists := userLimits.Users[username]; exists {
        return limit
    }
    return userLimits.DefaultLimit
}

func isWhitelisted(username string) bool {
    for _, w := range config.Whitelist {
        if w == username {
            return true
        }
    }
    return false
}

func disableUser(username string) bool {
    payload := map[string]interface{}{"status": "disabled"}
    return updateUserStatus(username, payload)
}

func enableUser(username string) bool {
    payload := map[string]interface{}{"status": "active"}
    return updateUserStatus(username, payload)
}

func updateUserStatus(username string, payload map[string]interface{}) bool {
    jsonData, _ := json.Marshal(payload)
    
    req, _ := http.NewRequest("PUT", config.PanelURL+"/api/user/"+username, bytes.NewBuffer(jsonData))
    req.Header.Set("Authorization", "Bearer "+authToken)
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := httpClient.Do(req)
    if err != nil {
        log.Printf("❌ Failed to update %s: %v", username, err)
        return false
    }
    defer resp.Body.Close()
    
    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyString := string(bodyBytes)
    
    if resp.StatusCode != 200 {
        log.Printf("❌ API Error for %s: Status=%d, Response=%s", username, resp.StatusCode, bodyString)
        return false
    }
    
    return true
}

func sendDailyStats() {
    now := time.Now()
    midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
    time.Sleep(time.Until(midnight))

    ticker := time.NewTicker(24 * time.Hour)
    for range ticker.C {
        statsMutex.Lock()
        stats := dailyStats
        dailyStats = Stats{LastReset: time.Now()}
        statsMutex.Unlock()

        message := fmt.Sprintf(`📊 گزارش روزانه

🚫 بلاک شده: %d
❌ رد شده: %d  
🟢 اتصالات: %d

📅 %s`,
            stats.BlockedToday,
            stats.RejectedToday,
            stats.ConnectedToday,
            time.Now().Format("2006-01-02"),
        )

        sendMessage(message)
    }
}

func handleSetLimit(chatID int64, args string) {
    var limit int
    fmt.Sscanf(args, "%d", &limit)
    if limit < 1 || limit > 20 {
        sendMessageTo(chatID, "❌ عدد باید بین 1 تا 20 باشد")
        return
    }
    userLimits.DefaultLimit = limit
    saveUserLimits()
    sendMessageTo(chatID, fmt.Sprintf("✅ حد پیش‌فرض IP به %d تغییر کرد", limit))
}

func handleSetRestore(chatID int64, args string) {
    var minutes int
    fmt.Sscanf(args, "%d", &minutes)
    if minutes < 10 || minutes > 1440 {
        sendMessageTo(chatID,"❌ زمان باید بین 10 تا 1440 دقیقه باشد")
        return
    }
    config.RestoreMinutes = minutes
    saveConfig()
    sendMessageTo(chatID, fmt.Sprintf("✅ زمان بازگردانی به %d دقیقه تغییر کرد", minutes))
}

func handleWhitelist(chatID int64, args string) {
    parts := strings.Fields(args)
    if len(parts) == 0 {
        sendMessageTo(chatID, "❌ دستور نامعتبر\n\n/whitelist add username\n/whitelist remove username\n/whitelist list")
        return
    }
    
    action := parts[0]
    
    switch action {
    case "add":
        if len(parts) < 2 {
            sendMessage("❌ نام کاربری را وارد کنید")
            return
        }
        username := parts[1]
        config.Whitelist = append(config.Whitelist, username)
        saveConfig()
        sendMessageTo(chatID, fmt.Sprintf("✅ %s به لیست استثنا اضافه شد (نامحدود)", username))
        
    case "remove":
        if len(parts) < 2 {
            sendMessage("❌ نام کاربری را وارد کنید")
            return
        }
        username := parts[1]
        newList := []string{}
        for _, w := range config.Whitelist {
            if w != username {
                newList = append(newList, w)
            }
        }
        config.Whitelist = newList
        saveConfig()
        sendMessage(fmt.Sprintf("✅ %s از لیست استثنا حذف شد", username))
        
    case "list":
        if len(config.Whitelist) == 0 {
            sendMessage("📋 لیست استثنا خالی است")
            return
        }
        var msg strings.Builder
        msg.WriteString("📋 لیست استثنا (نامحدود):\n\n")
        for _, w := range config.Whitelist {
            msg.WriteString(fmt.Sprintf("• %s\n", w))
        }
        sendMessage(msg.String())
        
    default:
        sendMessage("❌ دستور نامعتبر")
    }
}

func handleUserLimit(chatID int64, args string) {
    parts := strings.Fields(args)
    if len(parts) == 0 {
        sendMessageTo(chatID, "❌ دستور نامعتبر\n\n/userlimit set username limit\n/userlimit remove username\n/userlimit list\n/userlimit show username")
        return
    }
    action := parts[0]
    
    switch action {
    case "set":
        if len(parts) < 3 {
            sendMessageTo(chatID, "❌ مثال: /userlimit set Premium-User 5")
            return
        }
        username := parts[1]
        var limit int
        fmt.Sscanf(parts[2], "%d", &limit)
         if err := validateUsername(username); err != nil {
        sendMessageTo(chatID, fmt.Sprintf("❌ نام کاربری نامعتبر: %v", err))
        return
    }
        if limit < 1 || limit > 999 {
            sendMessageTo(chatID, "❌ لیمیت باید بین 1 تا 999 باشد")
            return
        }
        
        userLimits.Users[username] = limit
        saveUserLimits()
        sendMessageTo(chatID, fmt.Sprintf("✅ لیمیت IP برای %s به %d تنظیم شد", username, limit))
        
    case "remove":
        if len(parts) < 2 {
            sendMessageTo(chatID, "❌ نام کاربری را وارد کنید")
            return
        }
        username := parts[1]
         if err := validateUsername(username); err != nil {
        sendMessageTo(chatID, fmt.Sprintf("❌ نام کاربری نامعتبر: %v", err))
        return
    }
        delete(userLimits.Users, username)
        saveUserLimits()
        sendMessageTo(chatID, fmt.Sprintf("✅ لیمیت شخصی %s حذف شد (حالا از لیمیت پیش‌فرض استفاده می‌کند)", username))
        
    case "list":
        if len(userLimits.Users) == 0 {
            sendMessageTo(chatID, fmt.Sprintf("📋 لیست لیمیت های شخصی خالی است\n\n🔢 لیمیت پیش‌فرض: %d", userLimits.DefaultLimit))
            return
        }
        var msg strings.Builder
        msg.WriteString(fmt.Sprintf("📋 لیست لیمیت های شخصی:\n\n🔢 لیمیت پیش‌فرض: %d\n\n", userLimits.DefaultLimit))
        for user, limit := range userLimits.Users {
            msg.WriteString(fmt.Sprintf("• %s → %d IP\n", user, limit))
        }
        sendMessageTo(chatID, msg.String())
        
    case "show":
        if len(parts) < 2 {
            sendMessageTo(chatID, "❌ نام کاربری را وارد کنید")
            return
        }
        username := parts[1]
        limit := getUserLimit(username)
        
        if _, exists := userLimits.Users[username]; exists {
            sendMessageTo(chatID, fmt.Sprintf("👤 %s\n🔢 لیمیت: %d IP (شخصی)", username, limit))
        } else {
            sendMessageTo(chatID, fmt.Sprintf("👤 %s\n🔢 لیمیت: %d IP (پیش‌فرض)", username, limit))
        }
        
    default:
        sendMessageTo(chatID, "❌ دستور نامعتبر")
    }
}


func handleSettingsCommand(chatID int64) {
    msg := fmt.Sprintf(`⚙️ تنظیمات فعلی:


🔢 حد پیش‌فرض IP: %d
👤 تعداد لیمیت های شخصی: %d
⏰ زمان بازگردانی: %d دقیقه
📋 تعداد استثنا (whitelist): %d


دستورات:
/setlimit <عدد> - تغییر حد پیش‌فرض IP
/userlimit set <user> <limit> - تنظیم لیمیت شخصی
/userlimit list - نمایش لیمیت های شخصی
/setrestore <دقیقه> - تغییر زمان بازگردانی
/whitelist add <username> - افزودن استثنا (نامحدود)
/whitelist list - نمایش لیست استثنا`,
        userLimits.DefaultLimit,
        len(userLimits.Users),
        config.RestoreMinutes,
        len(config.Whitelist),
    )
    sendMessageTo(chatID, msg)
}


func saveConfig() {
    data, _ := yaml.Marshal(&config)
    ioutil.WriteFile("config.yaml", data, 0600)
}

func saveUserLimits() {
    data, _ := json.MarshalIndent(userLimits, "", "  ")
    ioutil.WriteFile("user-limits.json", data, 0600)
    log.Printf("✅ Saved user limits: default=%d, custom=%d users", userLimits.DefaultLimit, len(userLimits.Users))
}

func sendMessageTo(chatID int64, text string) {
    maxLength := 4000
    if len(text) <= maxLength {
        msg := tgbotapi.NewMessage(chatID, text)
        if _, err := bot.Send(msg); err != nil {
            log.Printf("❌ Failed to send message: %v", err)
        }
        return
    }
    
    parts := []string{}
    for len(text) > 0 {
        if len(text) <= maxLength {
            parts = append(parts, text)
            break
        }
        
        cutPoint := maxLength
        for i := maxLength - 1; i > 0; i-- {
            if text[i] == '\n' {
                cutPoint = i
                break
            }
        }
        
        parts = append(parts, text[:cutPoint])
        text = text[cutPoint:]
    }
    
    for i, part := range parts {
        if i > 0 {
            time.Sleep(1 * time.Second)
        }
        msg := tgbotapi.NewMessage(chatID, part)
        if _, err := bot.Send(msg); err != nil {
            log.Printf("❌ Failed to send message part %d: %v", i+1, err)
        }
    }
}

func sendMessage(text string) {
    sendMessageTo(config.TelegramChatID, text)
}
