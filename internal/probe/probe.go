package probe

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Result struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	Alive      bool
}

var (
	titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,120})</title>`)
	client  = &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 { return http.ErrUseLastResponse }
			return nil
		},
	}
)

func Probe(host string) *Result {
	r := &Result{}
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequest("GET", scheme+host, nil)
		if err != nil { continue }
		req.Header.Set("User-Agent", "Mozilla/5.0 XUE/1.0")
		resp, err := client.Do(req)
		if err != nil { continue }
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		r.URL        = resp.Request.URL.String()
		r.StatusCode = resp.StatusCode
		r.Server     = resp.Header.Get("Server")
		r.Alive      = true
		if m := titleRe.FindStringSubmatch(string(body)); len(m) > 1 {
			t := strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
			if len(t) > 60 { t = t[:57] + "..." }
			r.Title = t
		}
		break
	}
	return r
}
