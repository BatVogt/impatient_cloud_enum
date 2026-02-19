package enum_tools

import (
	"fmt"
	"strings"
)

const awsBanner = `
++++++++++++++++++++++++++
      amazon checks
++++++++++++++++++++++++++
`

const (
	s3URL   = "s3.amazonaws.com"
	appsURL = "awsapps.com"
)

// AWS_REGIONS is provided for reference; currently unused.
var AWS_REGIONS = []string{
	"amazonaws.com",
	"ap-east-1.amazonaws.com",
	"us-east-2.amazonaws.com",
	"us-west-1.amazonaws.com",
	"us-west-2.amazonaws.com",
	"ap-south-1.amazonaws.com",
	"ap-northeast-1.amazonaws.com",
	"ap-northeast-2.amazonaws.com",
	"ap-northeast-3.amazonaws.com",
	"ap-southeast-1.amazonaws.com",
	"ap-southeast-2.amazonaws.com",
	"ca-central-1.amazonaws.com",
	"cn-north-1.amazonaws.com.cn",
	"cn-northwest-1.amazonaws.com.cn",
	"eu-central-1.amazonaws.com",
	"eu-west-1.amazonaws.com",
	"eu-west-2.amazonaws.com",
	"eu-west-3.amazonaws.com",
	"eu-north-1.amazonaws.com",
	"sa-east-1.amazonaws.com",
}

// ---------------------------------------------------------------------------
// S3 checks
// ---------------------------------------------------------------------------

func printS3Response(result *HttpResult) bool {
	data := OutputData{Platform: "aws"}

	switch {
	case result.StatusCode == 404:
		// Not found — skip.
	case strings.Contains(result.Reason, "Bad Request"):
		// Malformed — skip.
	case result.StatusCode == 200:
		data.Msg = "OPEN S3 BUCKET"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
		ListBucketContents(result.URL)
	case result.StatusCode == 403:
		data.Msg = "Protected S3 Bucket"
		data.Target = result.URL
		data.Access = "protected"
		FmtOutput(data)
	case strings.Contains(result.Reason, "Slow Down"):
		fmt.Println("[!] You've been rate limited, skipping rest of check...")
		return true // breakout
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, result.Reason)
	}
	return false
}

func checkS3Buckets(names []string, threads int) {
	fmt.Println("[+] Checking for S3 buckets")
	start := StartTimer()

	var candidates []string
	for _, name := range names {
		candidates = append(candidates, fmt.Sprintf("%s.%s", name, s3URL))
	}

	GetURLBatch(candidates, false, printS3Response, threads, true)
	StopTimer(start)
}

// ---------------------------------------------------------------------------
// AWS Apps checks (WorkDocs, WorkMail, Connect, etc.)
// ---------------------------------------------------------------------------

func checkAWSApps(names []string, threads int, nameserver, nameserverFile string) {
	fmt.Println("[+] Checking for AWS Apps")
	start := StartTimer()

	var candidates []string
	for _, name := range names {
		candidates = append(candidates, fmt.Sprintf("%s.%s", name, appsURL))
	}

	validNames := FastDNSLookup(candidates, nameserver, nameserverFile, nil, threads)

	for _, name := range validNames {
		FmtOutput(OutputData{
			Platform: "aws",
			Msg:      "AWS App Found:",
			Target:   "https://" + name,
			Access:   "protected",
		})
	}

	StopTimer(start)
}

// ---------------------------------------------------------------------------
// RunAllAWS is the public entry-point called by main.
// ---------------------------------------------------------------------------

func RunAllAWS(names []string, cfg *Config) {
	fmt.Print(awsBanner)
	checkS3Buckets(names, cfg.Threads)
	checkAWSApps(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile)
}
