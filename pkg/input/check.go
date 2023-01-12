/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package input

import (
	"errors"
	"fmt"

	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	ErrMutexFlags    = errors.New("incompatible flags specified")
	ErrNoInput       = errors.New("no input specified")
	ErrNegativeValue = errors.New("must be positive")
)

func (options *Options) validateOptions() error {
	if options.Silent && options.Verbose {
		return fmt.Errorf("%w: %s and %s", ErrMutexFlags, "silent", "verbose")
	}

	if options.Input == "" && options.FileInput == "" && !fileutil.HasStdin() {
		return fmt.Errorf("%w", ErrNoInput)
	}

	if options.Concurrency <= 0 {
		return fmt.Errorf("%w", ErrNegativeValue)
	}

	return nil
}
