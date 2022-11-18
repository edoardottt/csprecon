package csprecon

import (
	"crypto/tls"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	TLSHandshakeTimeout = 10
	KeepAlive           = 30
	DomainRegex         = `.*[a-zA-Z\_\-0-9]+\.[a-z]+`
)

func checkCSP(url string, r *regexp.Regexp, client *http.Client) ([]string, error) {
	var (
		result    = []string{}
		headerCSP []string
		bodyCSP   []string
	)

	resp, err := client.Get(url)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	headerCSP = parseCSPHeader(resp.Header.Get("Content-Security-Policy"), r)
	if len(headerCSP) != 0 {
		bodyCSP = parseCSPBody("")
	}

	result = append(result, headerCSP...)
	result = append(result, bodyCSP...)

	return result, nil
}

func parseCSPHeader(input string, r *regexp.Regexp) []string {
	result := []string{}

	splitted := strings.Split(input, ";")

	for _, elem := range splitted {
		spaceSplit := strings.Split(elem, " ")
		for _, spaceElem := range spaceSplit {
			if r.Match([]byte(spaceElem)) {
				result = append(result, spaceElem)
			}
		}
	}

	return result
}

func parseCSPBody(input string) []string {
	result := []string{}

	return result
}

func customClient(timeout int) *http.Client {
	//ref: Copy and modify defaults from https://golang.org/src/net/http/transport.go
	//Note: Clients and Transports should only be created once and reused
	transport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			// Modify the time to wait for a connection to establish
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
