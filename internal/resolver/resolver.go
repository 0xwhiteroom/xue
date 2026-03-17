package resolver

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Host     string
	IPs      []string
	CNAME    string
	Resolved bool
}

func WildcardIPs(domain string) map[string]bool {
	rand.Seed(time.Now().UnixNano())
	test := fmt.Sprintf("%x.%s", rand.Int63(), domain)
	ips, err := net.LookupHost(test)
	if err != nil { return nil }
	m := map[string]bool{}
	for _, ip := range ips { m[ip] = true }
	return m
}

func Resolve(host string) Result {
	r := Result{Host: host}
	if cn, err := net.LookupCNAME(host); err == nil {
		r.CNAME = strings.TrimSuffix(cn, ".")
	}
	ips, err := net.LookupHost(host)
	if err != nil { return r }
	r.IPs      = ips
	r.Resolved = true
	return r
}

func ResolveAll(hosts []string, wildcardIPs map[string]bool, threads int) []Result {
	ch  := make(chan string, len(hosts))
	out := make(chan Result, len(hosts))
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range ch {
				r := Resolve(h)
				if !r.Resolved { out <- r; continue }
				if len(wildcardIPs) > 0 {
					allWild := true
					for _, ip := range r.IPs {
						if !wildcardIPs[ip] { allWild = false; break }
					}
					if allWild { continue }
				}
				out <- r
			}
		}()
	}
	for _, h := range hosts { ch <- h }
	close(ch)
	go func() { wg.Wait(); close(out) }()
	var results []Result
	for r := range out { results = append(results, r) }
	return results
}
