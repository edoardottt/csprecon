/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package input

// This file exposes unexported internals to the external test package. It is
// named export_test.go so it is compiled only for tests and skipped by the
// testpackage linter.

// ValidateOptions runs validateOptions (test wrapper).
func (options *Options) ValidateOptions() error { return options.validateOptions() }

// CheckProxy runs checkProxy (test wrapper).
func CheckProxy(proxy string) bool { return checkProxy(proxy) }
