package asn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Info struct {
	IP      string
	ASN     string
	Org     string
	Country string
}

var client = &http.Client{Timeout: 8 * time.Second}

func Lookup(ip string) *Info {
	info := &Info{IP: ip}
	if ip == "" { return info }
	req, err := http.NewRequest("GET", "https://ipinfo.io/"+ip+"/json", nil)
	if err != nil { return info }
	req.Header.Set("User-Agent", "XUE/1.0")
	resp, err := client.Do(req)
	if err != nil { return info }
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var data struct {
		Org     string `json:"org"`
		Country string `json:"country"`
	}
	if err := json.Unmarshal(body, &data); err != nil { return info }
	parts := strings.SplitN(data.Org, " ", 2)
	if len(parts) == 2 { info.ASN = parts[0]; info.Org = parts[1] } else { info.Org = data.Org }
	info.Country = data.Country
	return info
}

func Format(i *Info) string {
	if i.ASN == "" && i.Org == "" { return "" }
	return fmt.Sprintf("%s [%s] %s", i.ASN, i.Country, i.Org)
}
