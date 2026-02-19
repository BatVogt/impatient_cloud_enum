package enum_tools

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const azureBanner = `
++++++++++++++++++++++++++
       azure checks
++++++++++++++++++++++++++
`

// Known Azure domain suffixes.
const (
	blobURL     = "blob.core.windows.net"
	fileURL     = "file.core.windows.net"
	queueURL    = "queue.core.windows.net"
	tableURL    = "table.core.windows.net"
	mgmtURL     = "scm.azurewebsites.net"
	vaultURL    = "vault.azure.net"
	webappURL   = "azurewebsites.net"
	databaseURL = "database.windows.net"
	vmURL       = "cloudapp.azure.com"
)

// ---------------------------------------------------------------------------
// Storage-account response callback (shared by several checks)
// ---------------------------------------------------------------------------

func printAccountResponse(result *HttpResult) bool {
	data := OutputData{Platform: "azure"}
	reason := result.Reason
	body := result.Body

	switch {
	case result.StatusCode == 404,
		strings.Contains(reason, "The requested URI does not represent"):
		// Not found — skip.

	case strings.Contains(reason, "Server failed to authenticate the request"),
		strings.Contains(body, "Server failed to authenticate the request"):
		data.Msg = "Auth-Only Account"
		data.Target = result.URL
		data.Access = "protected"
		FmtOutput(data)

	case strings.Contains(reason, "The specified account is disabled"),
		strings.Contains(body, "The specified account is disabled"):
		data.Msg = "Disabled Account"
		data.Target = result.URL
		data.Access = "disabled"
		FmtOutput(data)

	case strings.Contains(reason, "Value for one of the query"),
		strings.Contains(body, "Value for one of the query"):
		data.Msg = "HTTP-OK Account"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)

	case strings.Contains(reason, "The account being accessed"),
		strings.Contains(body, "The account being accessed"):
		data.Msg = "HTTPS-Only Account"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)

	case strings.Contains(reason, "Unauthorized"),
		strings.Contains(body, "Unauthorized"):
		data.Msg = "Unauthorized Account"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)

	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d : %s\n",
			result.URL, result.StatusCode, reason)
	}
	return false
}

// ---------------------------------------------------------------------------
// Generic helper – most Azure account checks are identical in shape.
// ---------------------------------------------------------------------------

func checkAzureAccountType(names []string, threads int, nameserver, nameserverFile, domain, label string) []string {
	fmt.Printf("[+] Checking for Azure %s\n", label)
	start := StartTimer()

	alphaNum := regexp.MustCompile(`[^a-zA-Z0-9]`)
	var candidates []string
	for _, name := range names {
		if !alphaNum.MatchString(name) {
			candidates = append(candidates, name+"."+domain)
		}
	}

	validNames := FastDNSLookup(candidates, nameserver, nameserverFile, nil, threads)
	GetURLBatch(validNames, false, printAccountResponse, threads, true)
	StopTimer(start)

	// De-duplicate.
	seen := make(map[string]bool)
	var unique []string
	for _, n := range validNames {
		if !seen[n] {
			seen[n] = true
			unique = append(unique, n)
		}
	}
	return unique
}

// ---------------------------------------------------------------------------
// Container brute-force
// ---------------------------------------------------------------------------

func printContainerResponse(result *HttpResult) bool {
	data := OutputData{Platform: "azure"}
	reason := result.Reason
	body := result.Body

	// Early break-out conditions.
	if strings.Contains(reason, "The specified account is disabled") ||
		strings.Contains(body, "The specified account is disabled") {
		fmt.Println("    [!] Breaking out early, account disabled.")
		return true
	}
	if strings.Contains(reason, "not authorized to perform this operation") ||
		strings.Contains(reason, "not have sufficient permissions") ||
		strings.Contains(reason, "Public access is not permitted") ||
		strings.Contains(reason, "Server failed to authenticate the request") ||
		strings.Contains(body, "not authorized to perform this operation") ||
		strings.Contains(body, "not have sufficient permissions") ||
		strings.Contains(body, "Public access is not permitted") ||
		strings.Contains(body, "Server failed to authenticate the request") {
		fmt.Println("    [!] Breaking out early, auth required.")
		return true
	}
	if strings.Contains(reason, "Blob API is not yet supported") ||
		strings.Contains(body, "Blob API is not yet supported") {
		fmt.Println("    [!] Breaking out early, Hierarchical namespace account")
		return true
	}

	switch {
	case result.StatusCode == 404:
		// Not found.
	case result.StatusCode == 200:
		data.Msg = "OPEN AZURE CONTAINER"
		data.Target = result.URL
		data.Access = "public"
		FmtOutput(data)
		ListBucketContents(result.URL)
	case strings.Contains(reason, "One of the request inputs is out of range"),
		strings.Contains(body, "One of the request inputs is out of range"):
		// skip
	case strings.Contains(reason, "The request URI is invalid"),
		strings.Contains(body, "The request URI is invalid"):
		// skip
	default:
		fmt.Printf("    Unknown status codes being received from %s:\n       %d: %s\n",
			result.URL, result.StatusCode, reason)
	}
	return false
}

func bruteForceContainers(storageAccounts []string, bruteData string, threads int) {
	fmt.Printf("[*] Checking %d accounts for status before brute-forcing\n", len(storageAccounts))

	var validAccounts []string
	for _, acct := range storageAccounts {
		resp, err := http.Get("https://" + acct + "/")
		if err != nil {
			fmt.Printf("    [!] Connection error on https://%s: %v\n", acct, err)
			continue
		}
		resp.Body.Close()
		reason := extractReason(resp.Status)
		if strings.Contains(reason, "Server failed to authenticate the request") ||
			strings.Contains(reason, "The specified account is disabled") {
			continue
		}
		validAccounts = append(validAccounts, acct)
	}

	cleanNames := GetBrute(bruteData, 3, 63)
	start := StartTimer()

	fmt.Printf("[*] Brute-forcing container names in %d storage accounts\n", len(validAccounts))
	for _, acct := range validAccounts {
		fmt.Printf("[*] Brute-forcing %d container names in %s\n", len(cleanNames), acct)
		var candidates []string
		for _, name := range cleanNames {
			candidates = append(candidates, fmt.Sprintf("%s/%s/?restype=container&comp=list", acct, name))
		}
		GetURLBatch(candidates, true, printContainerResponse, threads, true)
	}
	StopTimer(start)
}

// ---------------------------------------------------------------------------
// Azure Websites
// ---------------------------------------------------------------------------

func checkAzureWebsites(names []string, nameserver string, threads int, nameserverFile string) {
	fmt.Println("[+] Checking for Azure Websites")
	start := StartTimer()

	var candidates []string
	for _, n := range names {
		candidates = append(candidates, n+"."+webappURL)
	}

	FastDNSLookup(candidates, nameserver, nameserverFile, func(hostname string) {
		FmtOutput(OutputData{
			Platform: "azure",
			Msg:      "Registered Azure Website DNS Name",
			Target:   hostname,
			Access:   "public",
		})
	}, threads)

	StopTimer(start)
}

// ---------------------------------------------------------------------------
// Azure Databases
// ---------------------------------------------------------------------------

func checkAzureDatabases(names []string, nameserver string, threads int, nameserverFile string) {
	fmt.Println("[+] Checking for Azure Databases")
	start := StartTimer()

	var candidates []string
	for _, n := range names {
		candidates = append(candidates, n+"."+databaseURL)
	}

	FastDNSLookup(candidates, nameserver, nameserverFile, func(hostname string) {
		FmtOutput(OutputData{
			Platform: "azure",
			Msg:      "Registered Azure Database DNS Name",
			Target:   hostname,
			Access:   "public",
		})
	}, threads)

	StopTimer(start)
}

// ---------------------------------------------------------------------------
// Azure Virtual Machines
// ---------------------------------------------------------------------------

func checkAzureVMs(names []string, nameserver string, threads int, nameserverFile string) {
	fmt.Println("[+] Checking for Azure Virtual Machines")
	start := StartTimer()

	regions := AzureRegions
	fmt.Printf("[*] Testing across %d regions defined in the config file\n", len(regions))

	for _, region := range regions {
		var candidates []string
		for _, n := range names {
			candidates = append(candidates, n+"."+region+"."+vmURL)
		}
		FastDNSLookup(candidates, nameserver, nameserverFile, func(hostname string) {
			FmtOutput(OutputData{
				Platform: "azure",
				Msg:      "Registered Azure Virtual Machine DNS Name",
				Target:   hostname,
				Access:   "public",
			})
		}, threads)
	}

	StopTimer(start)
}

// ---------------------------------------------------------------------------
// RunAllAzure is the public entry-point called by main.
// ---------------------------------------------------------------------------

func RunAllAzure(names []string, cfg *Config) {
	fmt.Print(azureBanner)

	validAccounts := checkAzureAccountType(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile, blobURL, "Storage Accounts")
	if len(validAccounts) > 0 && !cfg.QuickScan {
		bruteForceContainers(validAccounts, cfg.BruteData, cfg.Threads)
	}

	checkAzureAccountType(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile, fileURL, "File Accounts")
	checkAzureAccountType(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile, queueURL, "Queue Accounts")
	checkAzureAccountType(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile, tableURL, "Table Accounts")
	checkAzureAccountType(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile, mgmtURL, "App Management Accounts")
	checkAzureAccountType(names, cfg.Threads, cfg.Nameserver, cfg.NameserverFile, vaultURL, "Key Vault Accounts")

	checkAzureWebsites(names, cfg.Nameserver, cfg.Threads, cfg.NameserverFile)
	checkAzureDatabases(names, cfg.Nameserver, cfg.Threads, cfg.NameserverFile)
	checkAzureVMs(names, cfg.Nameserver, cfg.Threads, cfg.NameserverFile)
}
