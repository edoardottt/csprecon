package csprecon

import (
	"crypto/tls"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/edoardottt/golazy"
)

const (
	TLSHandshakeTimeout = 10
	KeepAlive           = 30
	DomainRegex         = `.*[a-zA-Z\_\-0-9]+\.[a-z]+`
)

func checkCSP(url, ua string, rCSP *regexp.Regexp, client *http.Client) ([]string, error) {
	var (
		result    = []string{}
		headerCSP []string
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}

	req.Header.Add("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	headerCSP = parseCSP(resp.Header.Get("Content-Security-Policy"), rCSP)
	result = append(result, headerCSP...)

	return result, nil
}

func parseCSP(input string, r *regexp.Regexp) []string {
	result := []string{}

	var err error

	splitted := strings.Split(input, ";")

	for _, elem := range splitted {
		spaceSplit := strings.Split(elem, " ")
		for _, spaceElem := range spaceSplit {
			if r.Match([]byte(spaceElem)) {
				if strings.Contains(spaceElem, "://") {
					spaceElem, err = golazy.GetHost(spaceElem)
					if err != nil {
						continue
					}
				}
				result = append(result, spaceElem)
			}
		}
	}

	return result
}

func customClient(timeout int) *http.Client {
	transport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: KeepAlive * time.Second,
		}).Dial,
		TLSHandshakeTimeout: TLSHandshakeTimeout * time.Second,
	}

	client := http.Client{
		Transport: &transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	return &client
}

func CompileRegex(regex string) *regexp.Regexp {
	r, _ := regexp.Compile(regex)

	return r
}

func domainOk(input string, domains []string) bool {
	for _, domain := range domains {
		if len(input) > len(domain)+1 && input[len(input)-len(domain)-1:] == "."+domain {
			return true
		}
	}

	return false
}
