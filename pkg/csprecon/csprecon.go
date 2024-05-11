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
	r.InWg.Add(1)

	go pushInput(r)
	r.InWg.Add(1)

	go execute(r)
	r.OutWg.Add(1)

	go pullOutput(r)
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
					if r.Options.Verbose {
						gologger.Error().Msgf("%s", err)
					}

					return
				}

				rl.Take()

				client := customClient(r.Options.Timeout)

				result, err := CheckCSP(targetURL, r.UserAgent, dregex, client)
				if err != nil {
					if r.Options.Verbose {
						gologger.Error().Msgf("%s", err)
					}

					return
				}

				if r.Options.JSON {
					if len(r.Options.Domain) != 0 {
						tempResult := []string{}

						for _, res := range result {
							if domainOk(res, r.Options.Domain) {
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
								if domainOk(resTrimmed, r.Options.Domain) {
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

	if r.Options.JSON {
		for o := range r.JSONOutput {
			r.OutWg.Add(1)

			go writeJSONOutput(r.OutWg, r.OutMutex, &r.Options, o)
		}
	} else {
		for o := range r.Output {
			if !r.Result.Printed(o) {
				r.OutWg.Add(1)

				go writeOutput(r.OutWg, r.OutMutex, &r.Options, o)
			}
		}
	}
}

func writeOutput(wg *sync.WaitGroup, m *sync.Mutex, options *input.Options, o string) {
	defer wg.Done()

	if options.FileOutput != "" && options.Output == nil {
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
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
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
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
		if _, err := options.Output.Write(out); err != nil && options.Verbose {
			gologger.Fatal().Msg(err.Error())
		}
	}

	m.Unlock()

	fmt.Println(string(out))
}
