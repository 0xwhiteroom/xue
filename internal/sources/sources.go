package sources

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Subdomain string
	Source    string
}

var client = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func get(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return nil, err }
	req.Header.Set("User-Agent", "Mozilla/5.0 XUE/1.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
}

func clean(s, domain string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	if !strings.HasSuffix(s, "."+domain) && s != domain { return "" }
	return s
}

func Run(domain string, out chan<- Result) {
	type srcFn func(string) []string
	srcs := map[string]srcFn{
		"crt.sh":      crtsh,
		"hackertarget": hackertarget,
		"alienvault":  alienvault,
		"rapiddns":    rapiddns,
		"anubis":      anubis,
		"threatcrowd": threatcrowd,
	}
	var wg sync.WaitGroup
	for name, fn := range srcs {
		wg.Add(1)
		go func(n string, f srcFn) {
			defer wg.Done()
			for _, s := range f(domain) {
				s = clean(s, domain)
				if s != "" {
					out <- Result{Subdomain: s, Source: n}
				}
			}
		}(name, fn)
	}
	wg.Wait()
}

func crtsh(domain string) []string {
	body, err := get(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil { return nil }
	var entries []struct{ NameValue string `json:"name_value"` }
	if err := json.Unmarshal(body, &entries); err != nil { return nil }
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			line = strings.TrimSpace(line)
			if !seen[line] { seen[line] = true; out = append(out, line) }
		}
	}
	return out
}

func hackertarget(domain string) []string {
	body, err := get(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
	if err != nil { return nil }
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ",", 2)
		if len(parts) > 0 { out = append(out, parts[0]) }
	}
	return out
}

func alienvault(domain string) []string {
	body, err := get(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
	if err != nil { return nil }
	var resp struct {
		PassiveDNS []struct{ Hostname string `json:"hostname"` } `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &resp); err != nil { return nil }
	var out []string
	for _, e := range resp.PassiveDNS { out = append(out, e.Hostname) }
	return out
}

func rapiddns(domain string) []string {
	body, err := get(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain))
	if err != nil { return nil }
	re := regexp.MustCompile(`<td><a[^>]*>([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)</a></td>`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(body), -1) { out = append(out, m[1]) }
	return out
}

func anubis(domain string) []string {
	body, err := get(fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain))
	if err != nil { return nil }
	var subs []string
	if err := json.Unmarshal(body, &subs); err != nil { return nil }
	return subs
}

func threatcrowd(domain string) []string {
	body, err := get(fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain))
	if err != nil { return nil }
	var resp struct{ Subdomains []string `json:"subdomains"` }
	if err := json.Unmarshal(body, &resp); err != nil { return nil }
	return resp.Subdomains
}
