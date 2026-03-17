package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Subdomain  string   `json:"subdomain"`
	IPs        []string `json:"ips,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	Source     string   `json:"source,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	HTTPTitle  string   `json:"http_title,omitempty"`
	HTTPServer string   `json:"http_server,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	ASNOrg     string   `json:"asn_org,omitempty"`
	Country    string   `json:"country,omitempty"`
	Takeover   string   `json:"takeover,omitempty"`
}

type Reporter struct {
	mu      sync.Mutex
	entries []Entry
	start   time.Time
	fTXT    *os.File
	fJSON   *os.File
	fJSONL  *os.File
	silent    bool
	showSrc   bool
	showIP    bool
	hasEnrich bool // true when probe/takeover/asn active
}

func New(txtOut, jsonOut, jsonlOut string, silent, showSrc, showIP, hasEnrich bool) (*Reporter, error) {
	r := &Reporter{start: time.Now(), silent: silent, showSrc: showSrc, showIP: showIP, hasEnrich: hasEnrich}
	open := func(p string) (*os.File, error) {
		if p == "" { return nil, nil }
		return os.Create(p)
	}
	var err error
	if r.fTXT,   err = open(txtOut);   err != nil { return nil, err }
	if r.fJSON,  err = open(jsonOut);  err != nil { return nil, err }
	if r.fJSONL, err = open(jsonlOut); err != nil { return nil, err }
	return r, nil
}

func (rep *Reporter) Close() {
	for _, f := range []*os.File{rep.fTXT, rep.fJSON, rep.fJSONL} {
		if f != nil { f.Close() }
	}
}

func (rep *Reporter) Add(e Entry) {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	rep.entries = append(rep.entries, e)

	// stdout already printed live during collection
	// only write to files here
	if rep.silent { return }

	// stderr — only show enriched info (basic subdomain already printed live)
	if rep.hasEnrich {
		line := fmt.Sprintf("  \033[92m\033[1m%s\033[0m", e.Subdomain)
		if rep.showIP && len(e.IPs) > 0 {
			line += fmt.Sprintf("  \033[96m[%s]\033[0m", strings.Join(e.IPs, ", "))
		}
		if e.Takeover != "" {
			line += fmt.Sprintf("  \033[91m\033[1m🎯 TAKEOVER: %s\033[0m", e.Takeover)
		}
		fmt.Fprintln(os.Stderr, line)
	}

	var sub []string
	if e.HTTPStatus != 0 {
		sc := httpCol(e.HTTPStatus)
		s  := fmt.Sprintf("%s[%d]\033[0m", sc, e.HTTPStatus)
		if e.HTTPTitle  != "" { s += " " + e.HTTPTitle }
		if e.HTTPServer != "" { s += fmt.Sprintf(" \033[2m(%s)\033[0m", e.HTTPServer) }
		sub = append(sub, s)
	}
	if e.ASN != "" {
		sub = append(sub, fmt.Sprintf("\033[2m[%s %s %s]\033[0m", e.ASN, e.Country, e.ASNOrg))
	}
	if e.CNAME != "" && e.CNAME != e.Subdomain {
		sub = append(sub, fmt.Sprintf("\033[2m→ %s\033[0m", e.CNAME))
	}
	if len(sub) > 0 {
		fmt.Fprintf(os.Stderr, "       \033[2m↳\033[0m %s\n", strings.Join(sub, "  "))
	}

	if rep.fTXT != nil { fmt.Fprintln(rep.fTXT, e.Subdomain) }
	if rep.fJSONL != nil {
		b, _ := json.Marshal(e)
		fmt.Fprintln(rep.fJSONL, string(b))
	}
}

func httpCol(code int) string {
	switch {
	case code >= 200 && code < 300: return "\033[92m\033[1m"
	case code >= 300 && code < 400: return "\033[93m"
	case code == 401 || code == 403: return "\033[91m\033[1m"
	default: return "\033[97m"
	}
}

func (rep *Reporter) Summary() {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if rep.silent { return }
	elapsed  := time.Since(rep.start)
	takeovers := 0
	for _, e := range rep.entries {
		if e.Takeover != "" { takeovers++ }
	}
	div := strings.Repeat("─", 54)
	fmt.Fprintf(os.Stderr, "\n  \033[2m%s\033[0m\n", div)
	fmt.Fprintf(os.Stderr, "  \033[92m\033[1m[✓]\033[0m  \033[1m%d\033[0m subdomains  \033[2m%.1fs\033[0m", len(rep.entries), elapsed.Seconds())
	if takeovers > 0 {
		fmt.Fprintf(os.Stderr, "  \033[91m\033[1m🎯 %d takeover(s)!\033[0m", takeovers)
	}
	fmt.Fprintf(os.Stderr, "\n  \033[2m%s\033[0m\n\n", div)
}

func (rep *Reporter) SaveJSON(path string) error {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	b, _ := json.MarshalIndent(rep.entries, "", "  ")
	_, err = f.Write(b)
	return err
}
