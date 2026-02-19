package enum_tools

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Logging globals
// ---------------------------------------------------------------------------

var (
	logFile   string
	logFormat string
	logMu     sync.Mutex
)

// ---------------------------------------------------------------------------
// Rate-limiter globals
// ---------------------------------------------------------------------------

var (
	rlCount     int64         // total HTTP requests made (across all batches)
	rlThreshold int64         // sleep every N requests (0 = disabled)
	rlSleep     time.Duration // duration to sleep
	rlPaused    int64         // 1 while sleeping, 0 otherwise
)

// InitRateLimiter configures the global HTTP rate limiter.
func InitRateLimiter(threshold int, sleep time.Duration) {
	rlThreshold = int64(threshold)
	rlSleep = sleep
}

// rateLimitCheck must be called before every HTTP request. When the
// cumulative request count crosses a multiple of the threshold the
// calling goroutine sleeps (other workers spin-wait until it's done).
func rateLimitCheck() {
	if rlThreshold <= 0 {
		return
	}

	// Wait while another goroutine is sleeping.
	for atomic.LoadInt64(&rlPaused) != 0 {
		time.Sleep(100 * time.Millisecond)
	}

	count := atomic.AddInt64(&rlCount, 1)
	if count%rlThreshold == 0 {
		atomic.StoreInt64(&rlPaused, 1)
		fmt.Printf("\n    [*] Rate limit: %d requests done, sleeping %v...\n", count, rlSleep)
		time.Sleep(rlSleep)
		atomic.StoreInt64(&rlPaused, 0)
	}
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// OutputData carries a single finding for display / logging.
type OutputData struct {
	Platform string `json:"platform"`
	Msg      string `json:"msg"`
	Target   string `json:"target"`
	Access   string `json:"access"`
}

// HttpResult is the data handed to HTTP-callback functions.
type HttpResult struct {
	URL         string // final URL after redirects
	StatusCode  int
	Reason      string // HTTP reason phrase (text after status code)
	Body        string
	OriginalURL string // URL before any redirects
}

// Config groups the runtime settings shared across check modules.
type Config struct {
	Threads        int
	Nameserver     string
	NameserverFile string
	BruteData      string // raw content of the brute-force wordlist
	QuickScan      bool
	RateLimitReqs  int           // sleep after this many HTTP requests (0 = disabled)
	RateLimitSleep time.Duration // how long to sleep when the threshold is hit
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

// InitLogfile sets up the global log file (append mode).
func InitLogfile(lf, format string) {
	if lf == "" {
		return
	}
	logFile = lf
	logFormat = format

	now := time.Now().Format("02/01/2006 15:04:05")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[!] Could not open log file: %v\n", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n\n#### CLOUD_ENUM %s ####\n", now)
}

// FmtOutput prints coloured output and optionally logs the finding.
func FmtOutput(data OutputData) {
	bold := "\033[1m"
	end := "\033[0m"
	var ansi string
	switch data.Access {
	case "public":
		ansi = bold + "\033[92m" // green
	case "protected":
		ansi = bold + "\033[33m" // orange
	case "disabled":
		ansi = bold + "\033[31m" // red
	default:
		ansi = bold
	}
	fmt.Printf("  %s%s: %s%s\n", ansi, data.Msg, data.Target, end)

	if logFile == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	switch logFormat {
	case "text":
		fmt.Fprintf(f, "%s: %s\n", data.Msg, data.Target)
	case "csv":
		w := csv.NewWriter(f)
		_ = w.Write([]string{data.Platform, data.Msg, data.Target, data.Access})
		w.Flush()
	case "json":
		_ = json.NewEncoder(f).Encode(data)
	}
}

// ---------------------------------------------------------------------------
// Domain helpers
// ---------------------------------------------------------------------------

// IsValidDomain does basic RFC length checks.
func IsValidDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if l := len(label); l < 1 || l > 63 {
			return false
		}
	}
	return true
}

// IsValidIP returns true when addr is a valid IPv4/IPv6 address.
func IsValidIP(addr string) bool {
	return net.ParseIP(addr) != nil
}

// ReadNameservers reads nameserver IPs from a file (one per line, # comments).
func ReadNameservers(filePath string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error: File '%s' not found.\n", filePath)
		os.Exit(1)
	}
	defer f.Close()

	var ns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ns = append(ns, line)
		}
	}
	if len(ns) == 0 {
		fmt.Println("Nameserver file is empty or only contains comments")
		os.Exit(1)
	}
	return ns
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func extractReason(status string) string {
	parts := strings.SplitN(status, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return status
}

// GetURLBatch sends HTTP GETs for every entry in urlList (prepending a
// protocol) and passes each result to callback. The callback returns true
// to abort the remaining work ("breakout").
//
// Uses a persistent worker-pool so all goroutines stay busy; one slow
// request no longer blocks the rest of the batch.
func GetURLBatch(urlList []string, useSSL bool, callback func(*HttpResult) bool, threads int, followRedirects bool) {
	total := len(urlList)
	if total == 0 {
		return
	}

	// Filter out domains that are obviously invalid.
	var valid []string
	for _, u := range urlList {
		if IsValidDomain(u) {
			valid = append(valid, u)
		}
	}
	total = len(valid)
	if total == 0 {
		return
	}

	proto := "http://"
	if useSSL {
		proto = "https://"
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        threads * 4,
			MaxIdleConnsPerHost: threads,
			MaxConnsPerHost:     threads,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	if !followRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Worker pool: feed URLs into a channel, N workers pull from it.
	jobs := make(chan string, threads*2)
	resultsCh := make(chan *HttpResult, threads*2)
	var done int64
	var aborted int64 // set to 1 on breakout

	var workerWg sync.WaitGroup
	for w := 0; w < threads; w++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for url := range jobs {
				if atomic.LoadInt64(&aborted) != 0 {
					atomic.AddInt64(&done, 1)
					continue // drain channel
				}
				rateLimitCheck()
				fullURL := proto + url
				resp, err := client.Get(fullURL)
				if err != nil {
					if !strings.Contains(err.Error(), "context canceled") {
						fmt.Printf("    [!] Connection error on %s: %v\n", url, err)
					}
					atomic.AddInt64(&done, 1)
					continue
				}
				// Read only first 8 KB — we only need headers / short XML.
				body := make([]byte, 8192)
				n, _ := io.ReadAtLeast(resp.Body, body, 1)
				resp.Body.Close()

				resultsCh <- &HttpResult{
					URL:         resp.Request.URL.String(),
					StatusCode:  resp.StatusCode,
					Reason:      extractReason(resp.Status),
					Body:        string(body[:max(n, 0)]),
					OriginalURL: fullURL,
				}
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	// Feeder goroutine.
	go func() {
		for _, u := range valid {
			if atomic.LoadInt64(&aborted) != 0 {
				break
			}
			jobs <- u
		}
		close(jobs)
	}()

	// Closer: when all workers finish, close results.
	go func() {
		workerWg.Wait()
		close(resultsCh)
	}()

	// Progress ticker.
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			d := atomic.LoadInt64(&done)
			fmt.Printf("\r    %d/%d complete...", d, total)
		}
	}()

	// Consume results.
	for r := range resultsCh {
		if callback(r) {
			atomic.StoreInt64(&aborted, 1)
		}
	}

	fmt.Printf("\r    %d/%d complete...\n", total, total)
	fmt.Print("\r                            \r")
}

// ListBucketContents fetches an open bucket URL and prints the keys found.
func ListBucketContents(bucket string) {
	resp, err := http.Get(bucket)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	keyRe := regexp.MustCompile(`<(?:Key|Name)>(.*?)</(?:Key|Name)>`)
	matches := keyRe.FindAllStringSubmatch(string(body), -1)

	// Strip query parameters before building full URLs.
	subRe := regexp.MustCompile(`\?.*`)
	bucket = subRe.ReplaceAllString(bucket, "")

	if len(matches) > 0 {
		fmt.Println("      FILES:")
		for _, m := range matches {
			fmt.Printf("      ->%s%s\n", bucket, m[1])
		}
	} else {
		fmt.Println("      ...empty bucket, so sad. :(")
	}
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

// useCustomNS reports whether a non-default nameserver was supplied.
func useCustomNS(nameserver, nameserverFile string) bool {
	return nameserverFile != "" || (nameserver != "" && nameserver != "1.1.1.1")
}

// newResolver builds a net.Resolver that talks to the supplied nameservers
// with short dial timeouts.
func newResolver(nameservers []string) *net.Resolver {
	var idx uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			i := atomic.AddUint64(&idx, 1) - 1
			ns := nameservers[i%uint64(len(nameservers))]
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", ns+":53")
		},
	}
}

// dnsLookup resolves a single name. Returns the name when found, "" for
// NXDOMAIN / timeout, or a sentinel for fatal errors.
func dnsLookup(resolver *net.Resolver, name string, timeout time.Duration) string {
	for tries := 0; tries < 2; tries++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, err := resolver.LookupHost(ctx, name)
		cancel()

		if err == nil {
			return name
		}

		// Unwrap to find *net.DNSError.
		var dnsErr *net.DNSError
		if e, ok := err.(*net.DNSError); ok {
			dnsErr = e
		} else if w, ok2 := err.(interface{ Unwrap() error }); ok2 {
			if e2, ok3 := w.Unwrap().(*net.DNSError); ok3 {
				dnsErr = e2
			}
		}
		if dnsErr != nil {
			if dnsErr.IsNotFound {
				return ""
			}
			if dnsErr.IsTimeout {
				continue
			}
			return "-#BREAKOUT_DNS_ERROR#-"
		}
		return "" // non-DNS error — skip
	}
	return ""
}

// FastDNSLookup resolves a list of names concurrently and returns those that
// exist. An optional callback is invoked for each valid name.
//
// DNS over UDP is lightweight, so this uses threads×10 concurrent workers
// (capped at 500) for much higher throughput than the HTTP pool.
func FastDNSLookup(names []string, nameserver, nameserverFile string, callback func(string), threads int) []string {
	total := len(names)
	if total == 0 {
		return nil
	}

	// Decide which resolver to use.
	// Default: system DNS (fast, cached, works through corporate proxies).
	// Custom: only when the user explicitly passes -ns (non-default) or -nsf.
	var resolver *net.Resolver
	var lookupTimeout time.Duration
	if useCustomNS(nameserver, nameserverFile) {
		var nsList []string
		if nameserverFile != "" {
			nsList = ReadNameservers(nameserverFile)
		} else {
			nsList = []string{nameserver}
		}
		resolver = newResolver(nsList)
		lookupTimeout = 3 * time.Second
		fmt.Printf("[*] Using custom nameserver(s) for DNS resolution\n")
	} else {
		resolver = net.DefaultResolver
		lookupTimeout = 5 * time.Second
	}

	fmt.Printf("[*] Brute-forcing a list of %d possible DNS names\n", total)

	// Filter out obviously invalid domains.
	var filtered []string
	for _, n := range names {
		if IsValidDomain(n) {
			filtered = append(filtered, n)
		}
	}
	total = len(filtered)
	if total == 0 {
		return nil
	}

	// DNS is lightweight — use far more workers than HTTP.
	dnsConcurrency := threads * 10
	if dnsConcurrency > 500 {
		dnsConcurrency = 500
	}
	if dnsConcurrency > total {
		dnsConcurrency = total
	}

	var (
		validNames []string
		validMu    sync.Mutex
		done       int64
	)

	jobs := make(chan string, dnsConcurrency*2)
	resultsCh := make(chan string, dnsConcurrency*2)

	var workerWg sync.WaitGroup
	for w := 0; w < dnsConcurrency; w++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for name := range jobs {
				resultsCh <- dnsLookup(resolver, name, lookupTimeout)
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	// Feeder goroutine.
	go func() {
		for _, n := range filtered {
			jobs <- n
		}
		close(jobs)
	}()

	// Closer.
	go func() {
		workerWg.Wait()
		close(resultsCh)
	}()

	// Progress ticker.
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			d := atomic.LoadInt64(&done)
			fmt.Printf("\r    %d/%d complete...", d, total)
		}
	}()

	// Consume results.
	for name := range resultsCh {
		if name == "" {
			continue
		}
		if name == "-#BREAKOUT_DNS_ERROR#-" {
			fmt.Println("\n    [!] Error querying nameservers! This could be a problem.")
			fmt.Println("    [!] If you're using a VPN, try setting -ns to your VPN's nameserver.")
			os.Exit(1)
		}
		if callback != nil {
			callback(name)
		}
		validMu.Lock()
		validNames = append(validNames, name)
		validMu.Unlock()
	}

	fmt.Printf("\r    %d/%d complete...\n", total, total)
	fmt.Print("\r                            \r")

	return validNames
}

// ---------------------------------------------------------------------------
// Brute-force wordlist helpers
// ---------------------------------------------------------------------------

// GetBrute cleans the raw wordlist data and returns entries matching the
// length / character constraints.
func GetBrute(data string, mini, maxi int) []string {
	banned := regexp.MustCompile(`[^a-z0-9_-]`)
	seen := make(map[string]bool)
	var clean []string

	for _, line := range strings.Split(data, "\n") {
		name := strings.TrimSpace(strings.ToLower(line))
		name = banned.ReplaceAllString(name, "")
		if name == "" {
			continue
		}
		if len(name) < mini || len(name) > maxi {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		clean = append(clean, name)
	}
	return clean
}

// ---------------------------------------------------------------------------
// Timer helpers
// ---------------------------------------------------------------------------

// StartTimer records the current time.
func StartTimer() time.Time {
	return time.Now()
}

// StopTimer prints elapsed time since start.
func StopTimer(start time.Time) {
	elapsed := time.Since(start)
	h := int(elapsed.Hours())
	m := int(elapsed.Minutes()) % 60
	s := int(elapsed.Seconds()) % 60
	fmt.Println()
	fmt.Printf(" Elapsed time: %02d:%02d:%02d\n", h, m, s)
	fmt.Println()
}
