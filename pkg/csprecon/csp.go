package csprecon

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/edoardottt/golazy"
)

const (
	TLSHandshakeTimeout = 10
	KeepAlive           = 30
	DomainRegex         = `(?i).*[a-z\_\-0-9]+\.[a-z]+`
)

// CheckCSP returns the list of domains parsed from a URL found in CSP.
func CheckCSP(url, ua string, rCSP *regexp.Regexp, client *http.Client) ([]string, error) {
	result := []string{}

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

	headerCSP := ParseCSP(resp.Header.Get("Content-Security-Policy"), rCSP)
	result = append(result, headerCSP...)

	if len(headerCSP) == 0 {
		bodyCSP := ParseBodyCSP(resp.Body, rCSP)
		result = append(result, bodyCSP...)
	}

	return result, nil
}

// ParseCSP returns the list of domains parsed from a raw CSP (string).
func ParseCSP(input string, r *regexp.Regexp) []string {
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

	return golazy.RemoveDuplicateValues(result)
}

// ParseBodyCSP returns the list of domains parsed from the CSP found in the meta tag
// of the input HTML body.
func ParseBodyCSP(body io.Reader, rCSP *regexp.Regexp) []string {
	result := []string{}

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		log.Fatal(err)
	}

	doc.Find("meta[http-equiv='Content-Security-Policy']").Each(func(i int, s *goquery.Selection) {
		contentCSP := s.AttrOr("content", "")
		if contentCSP != "" {
			result = ParseCSP(contentCSP, rCSP)
		}
	})

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
