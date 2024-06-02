/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package input

import (
	"errors"
	"fmt"
	"net/url"

	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	ErrMutexFlags    = errors.New("incompatible flags specified")
	ErrNoInput       = errors.New("no input specified")
	ErrNegativeValue = errors.New("must be positive")
	ErrCidrBadFormat = errors.New("malformed input CIDR")
	ErrMalformedURL  = errors.New("malformed input URL")
)

func (options *Options) validateOptions() error {
	if options.Silent && options.Verbose {
		return fmt.Errorf("%w: %s and %s", ErrMutexFlags, "silent", "verbose")
	}

	if options.Input == "" && options.FileInput == "" && !fileutil.HasStdin() {
		return fmt.Errorf("%w", ErrNoInput)
	}

	if options.Concurrency <= 0 {
		return fmt.Errorf("concurrency: %w", ErrNegativeValue)
	}

	if options.RateLimit != 0 && options.RateLimit <= 0 {
		return fmt.Errorf("rate limit: %w", ErrNegativeValue)
	}

	if options.Proxy != "" && !checkProxy(options.Proxy) {
		_, err := url.Parse(options.Proxy)
		return fmt.Errorf("proxy URL: %w", err)
	}

	return nil
}

func checkProxy(proxy string) bool {
	if len(proxy) == 0 {
		return false
	}

	_, err := url.Parse(proxy)
	return err == nil
}
