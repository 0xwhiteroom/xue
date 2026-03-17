package takeover

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Subdomain  string
	CNAME      string
	Service    string
	Vulnerable bool
}

type fp struct {
	service string
	cnames  []string
	bodies  []string
}

var fingerprints = []fp{
	{"GitHub Pages",   []string{"github.io","githubusercontent.com"}, []string{"There isn't a GitHub Pages site here"}},
	{"Heroku",         []string{"herokudns.com","herokuapp.com"},     []string{"No such app"}},
	{"Shopify",        []string{"myshopify.com"},                     []string{"Sorry, this shop is currently unavailable"}},
	{"Fastly",         []string{"fastly.net"},                        []string{"Fastly error: unknown domain"}},
	{"Ghost",          []string{"ghost.io"},                          []string{"The thing you were looking for is no longer here"}},
	{"Pantheon",       []string{"pantheonsite.io"},                   []string{"404 error unknown site!"}},
	{"Tumblr",         []string{"tumblr.com"},                        []string{"Whatever you were looking for doesn't currently exist"}},
	{"WordPress.com",  []string{"wordpress.com"},                     []string{"Do you want to register"}},
	{"AWS S3",         []string{"s3.amazonaws.com","s3-website"},     []string{"NoSuchBucket","The specified bucket does not exist"}},
	{"Azure",          []string{"azurewebsites.net","cloudapp.net"},  []string{"404 Web Site not found"}},
	{"Netlify",        []string{"netlify.com","netlify.app"},         []string{"Not Found - Request ID"}},
	{"Zendesk",        []string{"zendesk.com"},                       []string{"Help Center Closed"}},
	{"Surge.sh",       []string{"surge.sh"},                          []string{"project not found"}},
	{"Bitbucket",      []string{"bitbucket.io"},                      []string{"Repository not found"}},
	{"HubSpot",        []string{"hubspot.net","hs-sites.com"},        []string{"Domain is not configured"}},
	{"Squarespace",    []string{"squarespace.com"},                   []string{"No Such Account"}},
	{"Webflow",        []string{"webflow.io"},                        []string{"The page you are looking for doesn't exist"}},
	{"Vercel",         []string{"vercel.app","now.sh"},               []string{"The deployment could not be found"}},
	{"Intercom",       []string{"custom.intercom.help"},              []string{"Uh oh. That page doesn't exist."}},
	{"Unbounce",       []string{"unbouncepages.com"},                 []string{"The requested URL was not found on this server"}},
}

var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func Check(subdomain, cname string) *Result {
	r := &Result{Subdomain: subdomain, CNAME: cname}
	if cname == "" { return r }
	cnameLow := strings.ToLower(cname)
	var matched *fp
	for i := range fingerprints {
		for _, c := range fingerprints[i].cnames {
			if strings.Contains(cnameLow, c) { matched = &fingerprints[i]; break }
		}
		if matched != nil { break }
	}
	if matched == nil { return r }
	r.Service = matched.service
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequest("GET", scheme+subdomain, nil)
		if err != nil { continue }
		req.Header.Set("User-Agent", "Mozilla/5.0 XUE/1.0")
		resp, err := httpClient.Do(req)
		if err != nil { continue }
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		bodyLow := strings.ToLower(string(body))
		for _, b := range matched.bodies {
			if strings.Contains(bodyLow, strings.ToLower(b)) {
				r.Vulnerable = true
				return r
			}
		}
		break
	}
	return r
}
