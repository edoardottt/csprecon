/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package input

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	ErrMutexFlags    = errors.New("incompatible flags specified")
	ErrNoInput       = errors.New("no input specified")
	ErrNegativeValue = errors.New("must be positive")
	ErrCidrBadFormat = errors.New("malformed input CIDR")
	ErrMalformedURL  = errors.New("malformed input URL")
	ErrIsDirectory   = errors.New("is a directory")
	ErrOutputIsInput = errors.New("output file is also an input file")
	ErrBadProxy      = errors.New("malformed proxy URL")
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

	// A zero timeout would mean no timeout at all, so one stuck target could
	// hold up the run forever.
	if options.Timeout <= 0 {
		return fmt.Errorf("timeout: %w", ErrNegativeValue)
	}

	if options.RateLimit < 0 {
		return fmt.Errorf("rate limit: %w", ErrNegativeValue)
	}

	if options.Proxy != "" && !checkProxy(options.Proxy) {
		return fmt.Errorf("%w: %s (expected scheme://host[:port] with scheme http, https, socks5 or socks5h)",
			ErrBadProxy, options.Proxy)
	}

	if options.FileInput != "" {
		if err := checkInputFile(options.FileInput); err != nil {
			return fmt.Errorf("list file: %w", err)
		}
	}

	if options.BypassFile != "" {
		if err := checkInputFile(options.BypassFile); err != nil {
			return fmt.Errorf("bypass file: %w", err)
		}
	}

	if options.FileOutput != "" {
		if err := checkOutputFile(options.FileOutput, options.FileInput, options.BypassFile); err != nil {
			return fmt.Errorf("output file: %w", err)
		}
	}

	return nil
}

// checkProxy reports whether proxy is a URL the HTTP client can use: it needs
// a scheme the client supports and a host. "localhost:8080" parses as a URL
// with scheme "localhost" and no host, so it is rejected.
func checkProxy(proxy string) bool {
	u, err := url.Parse(proxy)
	if err != nil || u.Hostname() == "" {
		return false
	}

	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
		return true
	default:
		return false
	}
}

// checkInputFile catches an input file that cannot be read before the run
// starts. Only regular files are opened to test them, because opening a named
// pipe blocks; pipes such as -l <(cmd) are accepted as they are.
func checkInputFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return fmt.Errorf("%w: %s", ErrIsDirectory, path)
	}

	if info.Mode().IsRegular() {
		f, err := os.Open(path)
		if err != nil {
			return err
		}

		_ = f.Close()
	}

	return nil
}

// checkOutputFile catches an output file that can never be written before the
// run starts. Opening it empties it, so it must not be one of the inputs.
func checkOutputFile(path string, inputs ...string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		// The run creates the file, so its directory must exist.
		_, err = os.Stat(filepath.Dir(path))

		return err
	}

	if err != nil {
		return err
	}

	if info.IsDir() {
		return fmt.Errorf("%w: %s", ErrIsDirectory, path)
	}

	// Only a regular file is emptied, e.g. /dev/stdout is not.
	if !info.Mode().IsRegular() {
		return nil
	}

	for _, in := range inputs {
		if inInfo, err := os.Stat(in); err == nil && os.SameFile(info, inInfo) {
			return fmt.Errorf("%w: %s", ErrOutputIsInput, path)
		}
	}

	return nil
}
