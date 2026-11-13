/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package output

import (
	"sync"
)

// Result records the results already printed.
type Result struct {
	seen map[string]struct{}
	mu   *sync.Mutex
}

func New() Result {
	return Result{
		seen: map[string]struct{}{},
		mu:   &sync.Mutex{},
	}
}

// Printed reports whether result has been seen before, recording it as seen on
// the first call. It is safe for concurrent use: exactly one caller observes a
// given value as new.
func (o *Result) Printed(result string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, ok := o.seen[result]; ok {
		return true
	}

	o.seen[result] = struct{}{}

	return false
}
