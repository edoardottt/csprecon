package csprecon

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
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

	headerCSP = parseCSP(resp.Header.Get("Content-Security-Policy"), r)
	if len(headerCSP) == 0 {
		bodyCSP, err = parseCSPBody(resp.Body, r)
		if err != nil {
			return result, nil
		}
	}

	result = append(result, headerCSP...)
	result = append(result, bodyCSP...)

	return result, nil
}

func parseCSP(input string, r *regexp.Regexp) []string {
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

func parseCSPBody(input io.ReadCloser, r *regexp.Regexp) ([]string, error) {
	result := []string{}

	doc, err := html.Parse(input)
	if err != nil {
		return result, err
	}

	bodyString, err := io.ReadAll(input)
	if err != nil {
		return result, err
	}

	if strings.Contains(string(bodyString), `http-equiv="Content-Security-Policy"`) {
		// Recursively visit nodes in the parse tree
		var f func(*html.Node)
		f = func(n *html.Node) {
			if n.Data == "meta" {
				for _, a := range n.Attr {
					if a.Key == "content" {
						result = parseCSP(a.Val, r)
						break
					}
				}
			}

			for c := n.FirstChild; c != nil; c = c.NextSibling {
				f(c)
			}
		}
		f(doc)
	}

	return result, nil
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
