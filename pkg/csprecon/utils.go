/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/edoardottt/csprecon/pkg/input"
)

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

// PrepareURL takes as input a string and prepares
// the input URL in order to get the favicon icon.
func PrepareURL(inputURL string) (string, error) {
	if len(inputURL) < MinURLLength {
		return "", input.ErrMalformedURL
	}

	if !strings.Contains(inputURL, "://") {
		inputURL = "http://" + inputURL
	}

	u, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	return u.Scheme + "://" + u.Host + u.Path, nil
}
