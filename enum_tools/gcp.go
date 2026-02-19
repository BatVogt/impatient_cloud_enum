package enum_tools

import (
	"fmt"
	"strings"
	"sync"
)

const gcpBanner = `
++++++++++++++++++++++++++
      google checks
++++++++++++++++++++++++++
`

const (
	gcpURL     = "storage.googleapis.com"
	fbrtdbURL  = "firebaseio.com"
	appspotURL = "appspot.com"
	funcURL    = "cloudfunctions.net"
	fbappURL   = "firebaseapp.com"
)

// hasFuncs collects project/region URLs that have at least one Cloud Function.
var (
	hasFuncs   []string
	hasFuncsMu sync.Mutex
)

// ---------------------------------------------------------------------------
// GCP Bucket checks
// ---------------------------------------------------------------------------

func printBucketResponse(result *HttpResult) bool {
	data := OutputData{Platform: "gcp"}

	switch {
	case result.StatusCode == 404:
		// Not found.
	case result.StatusCode == 200:
		data.Msg = "OPEN GOOGLE BUCKET"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
		ListBucketContents(result.URL + "/")
	case result.StatusCode == 403:
		data.Msg = "Protected Google Bucket"
		data.Target = result.URL
		data.Access = "protected"
		FmtOutput(data)
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

func checkGCPBuckets(names []string, threads int) {
	fmt.Println("[+] Checking for Google buckets")
	start := StartTimer()

	var candidates []string
	for _, n := range names {
		candidates = append(candidates, gcpURL+"/"+n)
	}

	GetURLBatch(candidates, false, printBucketResponse, threads, true)
	StopTimer(start)
}

// ---------------------------------------------------------------------------
// Firebase Realtime Database
// ---------------------------------------------------------------------------

func printFBRTDBResponse(result *HttpResult) bool {
	data := OutputData{Platform: "gcp"}

	switch {
	case result.StatusCode == 404:
		// Not found.
	case result.StatusCode == 200:
		data.Msg = "OPEN GOOGLE FIREBASE RTDB"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
	case result.StatusCode == 401:
		data.Msg = "Protected Google Firebase RTDB"
		data.Target = result.URL
		data.Access = "protected"
		FmtOutput(data)
	case result.StatusCode == 402:
		data.Msg = "Payment required on Google Firebase RTDB"
		data.Target = result.URL
		data.Access = "disabled"
		FmtOutput(data)
	case result.StatusCode == 423:
		data.Msg = "The Firebase database has been deactivated."
		data.Target = result.URL
		data.Access = "disabled"
		FmtOutput(data)
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

func checkFBRTDB(names []string, threads int) {
	fmt.Println("[+] Checking for Google Firebase Realtime Databases")
	start := StartTimer()

	var candidates []string
	for _, n := range names {
		if !strings.Contains(n, ".") {
			candidates = append(candidates, n+"."+fbrtdbURL+"/.json")
		}
	}

	GetURLBatch(candidates, true, printFBRTDBResponse, threads, false)
	StopTimer(start)
}

// ---------------------------------------------------------------------------
// Firebase App
// ---------------------------------------------------------------------------

func printFBAppResponse(result *HttpResult) bool {
	data := OutputData{Platform: "gcp"}

	switch {
	case result.StatusCode == 404:
		// Not found.
	case result.StatusCode == 200:
		data.Msg = "OPEN GOOGLE FIREBASE APP"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

// CheckFBApp checks for Google Firebase Applications.
// NOTE: This function exists but is NOT called by RunAllGCP, matching the
// original Python project behaviour.
func CheckFBApp(names []string, threads int) {
	fmt.Println("[+] Checking for Google Firebase Applications")
	start := StartTimer()

	var candidates []string
	for _, n := range names {
		if !strings.Contains(n, ".") {
			candidates = append(candidates, n+"."+fbappURL)
		}
	}

	GetURLBatch(candidates, true, printFBAppResponse, threads, false)
	StopTimer(start)
}

// ---------------------------------------------------------------------------
// App Engine (appspot.com)
// ---------------------------------------------------------------------------

func printAppspotResponse(result *HttpResult) bool {
	data := OutputData{Platform: "gcp"}

	switch {
	case result.StatusCode == 404:
		// Not found.
	case result.StatusCode/100 == 5:
		data.Msg = "Google App Engine app with a 50x error"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
	case result.StatusCode == 200 || result.StatusCode == 302:
		if strings.Contains(result.URL, "accounts.google.com") {
			data.Msg = "Protected Google App Engine app"
			data.Target = result.OriginalURL
			data.Access = "protected"
		} else {
			data.Msg = "Open Google App Engine app"
			data.Target = result.URL
			data.Access = "public"
		}
		FmtOutput(data)
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

func checkAppspot(names []string, threads int) {
	fmt.Println("[+] Checking for Google App Engine apps")
	start := StartTimer()

	var candidates []string
	for _, n := range names {
		if !strings.Contains(n, ".") {
			candidates = append(candidates, n+"."+appspotURL)
		}
	}

	GetURLBatch(candidates, false, printAppspotResponse, threads, true)
	StopTimer(start)
}

// ---------------------------------------------------------------------------
// Cloud Functions (cloudfunctions.net)
// ---------------------------------------------------------------------------

func printFunctionsResponse1(result *HttpResult) bool {
	data := OutputData{Platform: "gcp"}

	switch {
	case result.StatusCode == 404:
		// Not found.
	case result.StatusCode == 302:
		data.Msg = "Contains at least 1 Cloud Function"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
		hasFuncsMu.Lock()
		hasFuncs = append(hasFuncs, result.URL)
		hasFuncsMu.Unlock()
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

func printFunctionsResponse2(result *HttpResult) bool {
	data := OutputData{Platform: "gcp"}

	switch {
	case strings.Contains(result.URL, "accounts.google.com/ServiceLogin"):
		// Redirected to Google login — skip.
	case result.StatusCode == 403 || result.StatusCode == 401:
		data.Msg = "Auth required Cloud Function"
		data.Target = result.URL
		data.Access = "protected"
		FmtOutput(data)
	case result.StatusCode == 405:
		data.Msg = "UNAUTHENTICATED Cloud Function (POST-Only)"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
	case result.StatusCode == 200 || result.StatusCode == 404:
		data.Msg = "UNAUTHENTICATED Cloud Function (GET-OK)"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

func checkFunctions(names []string, bruteData string, quickscan bool, threads int) {
	fmt.Println("[+] Checking for project/zones with Google Cloud Functions.")
	start := StartTimer()

	regions := GCPRegions
	fmt.Printf("[*] Testing across %d regions defined in the config file\n", len(regions))

	var candidates []string
	for _, region := range regions {
		for _, n := range names {
			candidates = append(candidates, region+"-"+n+"."+funcURL)
		}
	}

	// Reset global list.
	hasFuncsMu.Lock()
	hasFuncs = nil
	hasFuncsMu.Unlock()

	GetURLBatch(candidates, false, printFunctionsResponse1, threads, false)

	hasFuncsMu.Lock()
	found := make([]string, len(hasFuncs))
	copy(found, hasFuncs)
	hasFuncsMu.Unlock()

	if len(found) == 0 {
		StopTimer(start)
		return
	}
	if quickscan {
		return
	}

	fmt.Printf("[*] Brute-forcing function names in %d project/region combos\n", len(found))

	bruteStrings := GetBrute(bruteData, 1, 63)

	for _, fn := range found {
		fmt.Printf("[*] Brute-forcing %d function names in %s\n", len(bruteStrings), fn)
		// Strip protocol — GetURLBatch will prepend it.
		fn = strings.TrimPrefix(fn, "http://")
		fn = strings.TrimPrefix(fn, "https://")

		var c []string
		for _, b := range bruteStrings {
			c = append(c, fn+b+"/")
		}

		GetURLBatch(c, false, printFunctionsResponse2, threads, true)
	}

	StopTimer(start)
}

// ---------------------------------------------------------------------------
// RunAllGCP is the public entry-point called by main.
// ---------------------------------------------------------------------------

func RunAllGCP(names []string, cfg *Config) {
	fmt.Print(gcpBanner)

	checkGCPBuckets(names, cfg.Threads)
	checkFBRTDB(names, cfg.Threads)
	checkAppspot(names, cfg.Threads)
	checkFunctions(names, cfg.BruteData, cfg.QuickScan, cfg.Threads)
}
