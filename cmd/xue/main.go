package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"xue/internal/asn"
	"xue/internal/probe"
	"xue/internal/reporter"
	"xue/internal/resolver"
	"xue/internal/sources"
	"xue/internal/takeover"
)

func printBanner() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m██╗  ██╗██╗   ██╗███████╗\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m╚██╗██╔╝██║   ██║██╔════╝\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m ╚███╔╝ ██║   ██║█████╗  \033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m ██╔██╗ ██║   ██║██╔══╝  \033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m██╔╝ ██╗╚██████╔╝███████╗\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m╚═╝  ╚═╝ ╚═════╝ ╚══════╝\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m雪  XUE v1.0 — Subdomain Hunter\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[93mby 0xWHITEROOM 「0xホワイトルーム」\033[0m\n\n")
}

func printHelp() {
	printBanner()
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mUSAGE\033[0m\n")
	fmt.Fprintf(os.Stderr, "    xue -d <domain> [options]\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mSOURCES\033[0m  \033[2m(passive DNS — no API key needed)\033[0m\n")
	fmt.Fprintf(os.Stderr, "    crt.sh  hackertarget  alienvault  rapiddns  anubis  threatcrowd\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mFEATURES\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-resolve\033[0m         DNS resolve — show IPs\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-wt\033[0m              Wildcard DNS detect + filter\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-probe\033[0m           HTTP probe — status + title\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-takeover\033[0m        Subdomain takeover detect (20 services)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-asn\033[0m             ASN + org + country from IP\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mCONFIG\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-c <int>\033[0m         Threads (default 50)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-src\033[0m             Show source per subdomain\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-ip\033[0m              Show resolved IPs\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mOUTPUT\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-o <file>\033[0m        Save TXT\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-oj <file>\033[0m       Save JSON\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-ojl <file>\033[0m      Save JSONL\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-silent\033[0m          Subdomains only to stdout\n\n")
	fmt.Fprintf(os.Stderr, "  \033[92m\033[1mEXAMPLES\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxue -d example.com\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxue -d example.com -resolve -ip -src\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxue -d example.com -probe -takeover -asn\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxue -d example.com -silent | hx -td -waf\033[0m\n\n")
}

func main() {
	d         := flag.String("d",         "",    "")
	doResolve := flag.Bool("resolve",     false, "")
	doWild    := flag.Bool("wt",          false, "")
	doProbe   := flag.Bool("probe",       false, "")
	doTake    := flag.Bool("takeover",    false, "")
	doASN     := flag.Bool("asn",         false, "")
	c         := flag.Int("c",            50,    "")
	showSrc   := flag.Bool("src",         false, "")
	showIP    := flag.Bool("ip",          false, "")
	outTXT    := flag.String("o",         "",    "")
	outJSON   := flag.String("oj",        "",    "")
	outJSONL  := flag.String("ojl",       "",    "")
	silent    := flag.Bool("silent",      false, "")
	version   := flag.Bool("version",     false, "")

	flag.Usage = printHelp
	flag.Parse()

	if *version { fmt.Fprintln(os.Stderr, "xue 雪 v1.0  by FIN 「サイバー守護者」"); os.Exit(0) }
	if *d == "" { printHelp(); os.Exit(0) }

	domain := strings.ToLower(strings.TrimSpace(*d))
	domain  = strings.TrimPrefix(domain, "https://")
	domain  = strings.TrimPrefix(domain, "http://")
	domain  = strings.Split(domain, "/")[0]

	if *doProbe || *doTake || *doASN { *doResolve = true }
	if !*silent { printBanner() }

	if !*silent {
		fmt.Fprintf(os.Stderr, "  \033[96m[*]\033[0m Querying passive DNS for \033[1m\033[93m%s\033[0m\n\n", domain)
	}

	// Step 1: passive DNS
	rawCh  := make(chan sources.Result, 2000)
	seen   := map[string]bool{}
	var seenMu sync.Mutex
	var unique []string

	go func() { sources.Run(domain, rawCh); close(rawCh) }()

	for res := range rawCh {
		seenMu.Lock()
		if !seen[res.Subdomain] {
			seen[res.Subdomain] = true
			unique = append(unique, res.Subdomain)
			seenMu.Unlock()

			// ── Print immediately as found (live) ──
			src := ""
			if *showSrc { src = fmt.Sprintf("  \033[2m[%s]\033[0m", res.Source) }
			// always print to stdout (pipe friendly)
			fmt.Println(res.Subdomain)
			// print colored to stderr for terminal
			if !*silent {
				fmt.Fprintf(os.Stderr, "  \033[92m\033[1m%s\033[0m%s\n", res.Subdomain, src)
			}
		} else {
			seenMu.Unlock()
		}
	}

	if !*silent {
		fmt.Fprintf(os.Stderr, "\n  \033[92m[+]\033[0m Found \033[1m%d\033[0m unique subdomains\n", len(unique))
	}
	if len(unique) == 0 {
		if !*silent { fmt.Fprintf(os.Stderr, "  \033[93m[-]\033[0m No subdomains found.\n\n") }
		os.Exit(0)
	}

	// Step 2: wildcard check
	var wildcardIPs map[string]bool
	if *doWild || *doResolve {
		wildcardIPs = resolver.WildcardIPs(domain)
		if len(wildcardIPs) > 0 && !*silent {
			var ips []string
			for ip := range wildcardIPs { ips = append(ips, ip) }
			fmt.Fprintf(os.Stderr, "  \033[93m[!]\033[0m Wildcard detected → %s  (filtering...)\n", strings.Join(ips, ", "))
		}
	}

	// Step 3: resolve
	type subInfo struct {
		sub   string
		ips   []string
		cname string
	}
	var resolved []subInfo

	if *doResolve {
		if !*silent {
			fmt.Fprintf(os.Stderr, "  \033[96m[*]\033[0m Resolving \033[1m%d\033[0m subdomains  threads:\033[1m%d\033[0m\n", len(unique), *c)
		}
		results := resolver.ResolveAll(unique, wildcardIPs, *c)
		for _, r := range results {
			if !r.Resolved { continue }
			resolved = append(resolved, subInfo{r.Host, r.IPs, r.CNAME})
		}
		if !*silent {
			fmt.Fprintf(os.Stderr, "  \033[92m[+]\033[0m \033[1m%d\033[0m alive after DNS resolve\n\n", len(resolved))
		}
	} else {
		for _, s := range unique { resolved = append(resolved, subInfo{sub: s}) }
	}

	// Step 4: reporter
	hasEnrich := *doProbe || *doTake || *doASN || *showIP
	rep, err := reporter.New(*outTXT, *outJSON, *outJSONL, *silent, *showSrc, *showIP, hasEnrich)
	if err != nil { fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m output error: %s\n", err); os.Exit(1) }
	defer rep.Close()

	// Step 5: probe + takeover + ASN (only if enrichment flags set)
	entryCh := make(chan reporter.Entry, len(resolved)+1)
	var wg sync.WaitGroup
	sem     := make(chan struct{}, *c)

	for _, info := range resolved {
		wg.Add(1)
		sem <- struct{}{}
		go func(si subInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			e := reporter.Entry{Subdomain: si.sub, IPs: si.ips, CNAME: si.cname}
			if *doProbe {
				pr := probe.Probe(si.sub)
				if pr.Alive { e.HTTPStatus = pr.StatusCode; e.HTTPTitle = pr.Title; e.HTTPServer = pr.Server }
			}
			if *doTake {
				tr := takeover.Check(si.sub, si.cname)
				if tr.Vulnerable { e.Takeover = tr.Service }
			}
			if *doASN && len(si.ips) > 0 {
				ai := asn.Lookup(si.ips[0])
				e.ASN = ai.ASN; e.ASNOrg = ai.Org; e.Country = ai.Country
			}
			entryCh <- e
		}(info)
	}
	go func() { wg.Wait(); close(entryCh) }()
	for e := range entryCh { rep.Add(e) }

	if *outJSON != "" {
		if err := rep.SaveJSON(*outJSON); err != nil {
			fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m JSON save: %s\n", err)
		} else if !*silent {
			fmt.Fprintf(os.Stderr, "  \033[92m[+]\033[0m Saved → %s\n", *outJSON)
		}
	}
	rep.Summary()
}
