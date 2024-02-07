/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import "go.uber.org/ratelimit"

func rateLimiter(r *Runner) ratelimit.Limiter {
	var ratelimiter ratelimit.Limiter
	if r.Options.RateLimit > 0 {
		ratelimiter = ratelimit.New(r.Options.RateLimit)
	} else {
		ratelimiter = ratelimit.NewUnlimited()
	}

	return ratelimiter
}
