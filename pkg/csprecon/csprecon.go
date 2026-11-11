/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/csprecon/pkg/output"
	"github.com/edoardottt/golazy"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

const (
	DefaultFilePermission = 0644
)

type Runner struct {
	Input      chan string
	Output     chan string
	JSONOutput chan []string
	Result     output.Result
	UserAgent  string
	InWg       *sync.WaitGroup
	OutWg      *sync.WaitGroup
	Options    input.Options
	OutMutex   *sync.Mutex
	Bypass     map[string]string
}

func New(options *input.Options) Runner {
	if options.FileOutput != "" {
		_, err := os.Create(options.FileOutput)
		if err != nil {
			gologger.Error().Msgf("%s", err)
		}
	}

	return Runner{
		Input:      make(chan string, options.Concurrency),
		Output:     make(chan string, options.Concurrency),
		JSONOutput: make(chan []string, options.Concurrency),
		Result:     output.New(),
		UserAgent:  golazy.GenerateRandomUserAgent(),
		InWg:       &sync.WaitGroup{},
		OutWg:      &sync.WaitGroup{},
		Options:    *options,
		OutMutex:   &sync.Mutex{},
	}
}

func (r *Runner) Run() {
	if r.Options.Bypass {
		r.loadBypassData()
	}

	r.OutWg.Add(1)

	go pullOutput(r)

	r.InWg.Add(1)

	go execute(r)

	r.InWg.Add(1)

	go pushInput(r)

	r.InWg.Wait()

	close(r.Output)
	close(r.JSONOutput)
	r.OutWg.Wait()
}

func pushInput(r *Runner) {
	defer r.InWg.Done()

	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if r.Options.Cidr {
				ips, err := handleCIDRInput(scanner.Text())
				if err != nil {
					gologger.Error().Msg(err.Error())
				} else {
					for _, ip := range ips {
						r.Input <- ip
					}
				}
			} else {
				r.Input <- scanner.Text()
			}
		}
	}

	if r.Options.FileInput != "" {
		for _, line := range golazy.RemoveDuplicateValues(golazy.ReadFileLineByLine(r.Options.FileInput)) {
			if r.Options.Cidr {
				ips, err := handleCIDRInput(line)
				if err != nil {
					gologger.Error().Msg(err.Error())
				} else {
					for _, ip := range ips {
						r.Input <- ip
					}
				}
			} else {
				r.Input <- line
			}
		}
	}

	if r.Options.Input != "" {
		if r.Options.Cidr {
			ips, err := handleCIDRInput(r.Options.Input)
			if err != nil {
				gologger.Error().Msg(err.Error())
			} else {
				for _, ip := range ips {
					r.Input <- ip
				}
			}
		} else {
			r.Input <- r.Options.Input
		}
	}

	close(r.Input)
}

func execute(r *Runner) {
	defer r.InWg.Done()

	dregex := CompileRegex(DomainRegex)
	rl := rateLimiter(r)

	for i := 0; i < r.Options.Concurrency; i++ {
		r.InWg.Add(1)

		go func() {
			defer r.InWg.Done()

			for value := range r.Input {
				targetURL, err := PrepareURL(value)
				if err != nil {
					gologger.Error().Msgf("%s", err)

					continue
				}

				rl.Take()

				client, err := customClient(&r.Options)
				if err != nil {
					gologger.Error().Msgf("%s", err)

					continue
				}

				result, err := CheckCSP(targetURL, r.UserAgent, dregex, client)
				if err != nil {
					if r.Options.Verbose {
						gologger.Error().Msgf("%s", err)
					}

					continue
				}

				if r.Options.JSON {
					if len(r.Options.Domain) != 0 {
						tempResult := []string{}

						for _, res := range result {
							if DomainOk(res, r.Options.Domain) {
								tempResult = append(tempResult, res)
							}
						}

						r.JSONOutput <- append(tempResult, targetURL)
					} else {
						r.JSONOutput <- append(result, targetURL)
					}
				} else {
					for _, res := range result {
						if resTrimmed := strings.TrimSpace(res); resTrimmed != "" {
							if len(r.Options.Domain) != 0 {
								if DomainOk(resTrimmed, r.Options.Domain) {
									r.Output <- resTrimmed
								}
							} else {
								r.Output <- resTrimmed
							}
						}
					}
				}
			}
		}()
	}
}

func pullOutput(r *Runner) {
	defer r.OutWg.Done()

	// pullOutput runs in a single goroutine, so a plain map is enough to report
	// each bypass gadget only once.
	bypassSeen := map[string]struct{}{}

	if r.Options.JSON {
		for o := range r.JSONOutput {
			r.OutWg.Add(1)

			if r.Options.Bypass {
				// The last element is the target URL, the rest are domains.
				for _, domain := range o[:max(len(o)-1, 0)] {
					r.reportBypass(domain, bypassSeen)
				}
			}

			go writeJSONOutput(r.OutWg, r.OutMutex, &r.Options, o)
		}
	} else {
		for o := range r.Output {
			if !r.Result.Printed(o) {
				r.OutWg.Add(1)

				if r.Options.Bypass {
					r.reportBypass(o, bypassSeen)
				}

				go writeOutput(r.OutWg, r.OutMutex, &r.Options, o)
			}
		}
	}
}

// loadBypassData downloads the CSP bypass dataset once before the scan starts.
func (r *Runner) loadBypassData() {
	client, err := customClient(&r.Options)
	if err != nil {
		gologger.Error().Msgf("could not build client for CSP bypass data: %s", err)

		return
	}

	gadgets, err := FetchBypassData(client, r.UserAgent)
	if err != nil {
		gologger.Error().Msgf("could not load CSP bypass data: %s", err)

		return
	}

	r.Bypass = gadgets

	gologger.Info().Msgf("Loaded %d CSP bypass gadgets", len(gadgets))
}

// reportBypass prints the known bypass gadget for a domain, at most once.
func (r *Runner) reportBypass(domain string, seen map[string]struct{}) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}

	if _, ok := seen[domain]; ok {
		return
	}

	seen[domain] = struct{}{}

	if code, ok := LookupBypass(domain, r.Bypass); ok {
		gologger.Info().Msgf("[bypass] %s %s", domain, code)
	}
}

func writeOutput(wg *sync.WaitGroup, m *sync.Mutex, options *input.Options, o string) {
	defer wg.Done()

	if options.FileOutput != "" && options.Output == nil {
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_RDWR|os.O_APPEND, DefaultFilePermission)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}

		options.Output = file
	}

	m.Lock()

	if options.Output != nil {
		if _, err := options.Output.Write([]byte(o + "\n")); err != nil && options.Verbose {
			gologger.Fatal().Msg(err.Error())
		}
	}

	m.Unlock()

	fmt.Println(o)
}

func writeJSONOutput(wg *sync.WaitGroup, m *sync.Mutex, options *input.Options, o []string) {
	defer wg.Done()

	if options.FileOutput != "" && options.Output == nil {
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_RDWR|os.O_APPEND, DefaultFilePermission)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}

		options.Output = file
	}

	url, result, err := output.PrepareJSONOutput(o)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	out, err := output.FormatJSON(url, result)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	m.Lock()

	if options.Output != nil {
		if _, err := options.Output.Write(append(out, byte('\n'))); err != nil && options.Verbose {
			gologger.Fatal().Msg(err.Error())
		}
	}

	m.Unlock()

	fmt.Println(string(out))
}
