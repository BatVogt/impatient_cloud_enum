package main

import (
	"bufio"
	"embed"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BatVogt/impatient_cloud_enum/enum_tools"
)

//go:embed enum_tools/fuzz.txt
var fuzzFS embed.FS

const banner = `
##########################
    impatient_cloud_enum
   based on github.com/initstring
##########################

`

// ---------------------------------------------------------------------------
// Flag helpers
// ---------------------------------------------------------------------------

// stringSlice allows the -k flag to be specified multiple times.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

type cliArgs struct {
	keywords       []string
	mutationsFile  string
	bruteFile      string
	threads        int
	nameserver     string
	nameserverFile string
	logfile        string
	logFormat      string
	disableAWS     bool
	disableAzure   bool
	disableGCP     bool
	quickScan      bool
	rateLimitReqs  int
	rateLimitSleep int
}

func parseArguments() *cliArgs {
	args := &cliArgs{}

	var keywords stringSlice
	var keyfile string

	flag.Var(&keywords, "k", "Keyword. Can use flag multiple times.")
	flag.StringVar(&keyfile, "kf", "", "Input file with a single keyword per line.")
	flag.StringVar(&args.mutationsFile, "m", "", "Mutations file (default: embedded fuzz.txt).")
	flag.StringVar(&args.bruteFile, "b", "", "Brute-force list for Azure containers (default: embedded fuzz.txt).")
	flag.IntVar(&args.threads, "t", 25, "Concurrent workers for HTTP/DNS brute-force. Default = 25.")
	flag.StringVar(&args.nameserver, "ns", "1.1.1.1", "DNS server for brute-force. Default: system DNS (pass a custom IP to override).")
	flag.StringVar(&args.nameserverFile, "nsf", "", "Path to file containing nameserver IPs.")
	flag.StringVar(&args.logfile, "l", "", "Appends found items to specified file.")
	flag.StringVar(&args.logFormat, "f", "text", "Format for log file (text, json, csv). Default: text.")
	flag.BoolVar(&args.disableAWS, "disable-aws", false, "Disable Amazon checks.")
	flag.BoolVar(&args.disableAzure, "disable-azure", false, "Disable Azure checks.")
	flag.BoolVar(&args.disableGCP, "disable-gcp", false, "Disable Google checks.")
	flag.BoolVar(&args.quickScan, "qs", false, "Disable all mutations and second-level scans.")
	flag.IntVar(&args.rateLimitReqs, "rl", 8000, "Sleep after this many HTTP requests (0 = disabled). Default 8000.")
	flag.IntVar(&args.rateLimitSleep, "rls", 240, "Seconds to sleep when rate limit is hit (default 240).")

	flag.Parse()

	// Must supply either -k or -kf.
	if len(keywords) == 0 && keyfile == "" {
		fmt.Println("[!] You must provide keywords via -k or a keyword file via -kf")
		flag.Usage()
		os.Exit(1)
	}
	if len(keywords) > 0 && keyfile != "" {
		fmt.Println("[!] Use either -k or -kf, not both")
		os.Exit(1)
	}

	// Read keywords from file if needed.
	if keyfile != "" {
		f, err := os.Open(keyfile)
		if err != nil {
			fmt.Printf("[!] Cannot access keyword file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				keywords = append(keywords, line)
			}
		}
		if len(keywords) == 0 {
			fmt.Println("[!] Keyword file is empty")
			os.Exit(1)
		}
	}
	args.keywords = keywords

	// Validate mutations file.
	if args.mutationsFile != "" {
		if _, err := os.Stat(args.mutationsFile); err != nil {
			fmt.Printf("[!] Cannot access mutations file: %s\n", args.mutationsFile)
			os.Exit(1)
		}
	}
	// Validate brute file.
	if args.bruteFile != "" {
		if _, err := os.Stat(args.bruteFile); err != nil {
			fmt.Println("[!] Cannot access brute-force file, exiting")
			os.Exit(1)
		}
	}

	// Validate log file.
	if args.logfile != "" {
		info, err := os.Stat(args.logfile)
		if err == nil && info.IsDir() {
			fmt.Println("[!] Can't specify a directory as the logfile, exiting.")
			os.Exit(1)
		}
		// Verify format.
		switch args.logFormat {
		case "text", "json", "csv":
		default:
			fmt.Println("[!] Sorry! Allowed log formats: 'text', 'json', or 'csv'")
			os.Exit(1)
		}
		enum_tools.InitLogfile(args.logfile, args.logFormat)
	}

	return args
}

// ---------------------------------------------------------------------------
// Name building
// ---------------------------------------------------------------------------

func cleanText(text string) string {
	banned := regexp.MustCompile(`[^a-z0-9.\-]`)
	return banned.ReplaceAllString(strings.ToLower(text), "")
}

func appendName(name string, names *[]string) {
	if len(name) <= 63 {
		*names = append(*names, name)
	}
}

func buildNames(baseList, mutations []string) []string {
	var names []string
	for _, base := range baseList {
		base = cleanText(base)
		appendName(base, &names)
		for _, mut := range mutations {
			mut = cleanText(mut)
			appendName(base+mut, &names)
			appendName(base+"."+mut, &names)
			appendName(base+"-"+mut, &names)
			appendName(mut+base, &names)
			appendName(mut+"."+base, &names)
			appendName(mut+"-"+base, &names)
		}
	}
	fmt.Printf("[+] Mutated results: %d items\n", len(names))
	return names
}

// readFileOrEmbedded returns the content of a user-supplied file, or falls
// back to the embedded fuzz.txt.
func readFileOrEmbedded(path string) string {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("[!] Cannot read file %s: %v\n", path, err)
			os.Exit(1)
		}
		return string(data)
	}
	data, _ := fuzzFS.ReadFile("enum_tools/fuzz.txt")
	return string(data)
}

func readMutations(path string) []string {
	raw := readFileOrEmbedded(path)
	lines := strings.Split(raw, "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	fmt.Printf("[+] Mutations list imported: %d items\n", len(out))
	return out
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	args := parseArguments()
	fmt.Print(banner)

	// Status message.
	fmt.Printf("Keywords:    %s\n", strings.Join(args.keywords, ", "))
	if args.quickScan {
		fmt.Println("Mutations:   NONE! (Using quickscan)")
	} else {
		if args.mutationsFile != "" {
			fmt.Printf("Mutations:   %s\n", args.mutationsFile)
		} else {
			fmt.Println("Mutations:   (embedded fuzz.txt)")
		}
	}
	if args.bruteFile != "" {
		fmt.Printf("Brute-list:  %s\n", args.bruteFile)
	} else {
		fmt.Println("Brute-list:  (embedded fuzz.txt)")
	}
	fmt.Println()

	// Initialise rate limiter.
	if args.rateLimitReqs > 0 {
		enum_tools.InitRateLimiter(args.rateLimitReqs, time.Duration(args.rateLimitSleep)*time.Second)
		fmt.Printf("Rate-limit: sleep %ds every %d HTTP requests\n", args.rateLimitSleep, args.rateLimitReqs)
	}

	// Build mutated name list.
	var mutations []string
	if !args.quickScan {
		mutations = readMutations(args.mutationsFile)
	}
	names := buildNames(args.keywords, mutations)

	// Build config for check modules.
	bruteData := readFileOrEmbedded(args.bruteFile)
	cfg := &enum_tools.Config{
		Threads:        args.threads,
		Nameserver:     args.nameserver,
		NameserverFile: args.nameserverFile,
		BruteData:      bruteData,
		QuickScan:      args.quickScan,
	}

	// Run checks.
	if !args.disableAWS {
		enum_tools.RunAllAWS(names, cfg)
	}
	if !args.disableAzure {
		enum_tools.RunAllAzure(names, cfg)
	}
	if !args.disableGCP {
		enum_tools.RunAllGCP(names, cfg)
	}

	fmt.Println("\n[+] All done, happy hacking!")
}
