/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/csprecon/pkg/output"
	"github.com/edoardottt/golazy"
	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"golang.org/x/term"
)

const (
	DefaultFilePermission = 0644
)

// ErrAllTargetsFailed is returned by Run when no target could be scanned.
var ErrAllTargetsFailed = errors.New("no target could be scanned")

type Runner struct {
	Input     chan string
	Output    chan string
	Result    output.Result
	UserAgent string
	InWg      *sync.WaitGroup
	OutWg     *sync.WaitGroup
	Options   input.Options
	gadgets   *gadgetDB
	client    *http.Client
	outFile   *os.File     // the -o file, nil without -o
	color     bool         // highlight bypass lines on stdout
	scanned   *atomic.Bool // some target was scanned
	failed    *atomic.Bool // some target could not be scanned
}

func New(options *input.Options) Runner {
	// One HTTP client for the whole run, shared by every worker (http.Client is
	// safe for concurrent use). Its transport pools and reuses connections and
	// caps how many idle ones are kept.
	client, err := customClient(options)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}

	r := Runner{
		Input:     make(chan string, options.Concurrency),
		Output:    make(chan string, options.Concurrency),
		Result:    output.New(),
		UserAgent: golazy.GenerateRandomUserAgent(),
		InWg:      &sync.WaitGroup{},
		OutWg:     &sync.WaitGroup{},
		Options:   *options,
		client:    client,
		scanned:   &atomic.Bool{},
		failed:    &atomic.Bool{},
		// Colors only on a terminal: piped or redirected output, which is
		// what gets grepped or fed to other tools, stays plain.
		color: !options.JSON && term.IsTerminal(int(os.Stdout.Fd())),
	}

	if bypassEnabled(options) {
		db, src, err := loadGadgets(options)
		if err != nil {
			// Loading the gadget dataset is required for the bypass feature:
			// without it the results would be silently incomplete, so stop.
			gologger.Fatal().Msgf("bypass: %s", err)
		}

		r.gadgets = db

		if src == "cache" {
			gologger.Warning().Msg("bypass: live fetch failed, using cached CSPBypass data")
		}

		gologger.Debug().Msgf("bypass: loaded %d gadgets (%s)", db.count(), src)
	}

	// Opening -o empties it, so it is opened only after every setup step that
	// can abort the run: a failed run must not wipe the previous results.
	if options.FileOutput != "" {
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, DefaultFilePermission)
		if err != nil {
			gologger.Fatal().Msgf("output file: %s", err)
		}

		r.outFile = file
	}

	return r
}

// bypassEnabled reports whether the bypass feature is active: either -b/--bypass
// or -bf/--bypass-file was provided.
func bypassEnabled(o *input.Options) bool {
	return o.Bypass || o.BypassFile != ""
}

// Run scans every target. It fails when the output file cannot be closed or
// when not a single target could be scanned.
func (r *Runner) Run() error {
	r.OutWg.Add(1)

	go pullOutput(r)

	r.InWg.Add(1)

	go execute(r)

	r.InWg.Add(1)

	go pushInput(r)

	r.InWg.Wait()

	// Every request is done: release the pooled keep-alive connections now
	// instead of leaving them open until the idle timeout.
	r.client.CloseIdleConnections()

	close(r.Output)
	r.OutWg.Wait()

	if r.outFile != nil {
		// Close can report a write that failed late, e.g. on a network disk.
		if err := r.outFile.Close(); err != nil {
			return fmt.Errorf("output file: %w", err)
		}
	}

	// Most target errors are shown only with -v, so without this a run in
	// which every target failed would look like a run that found nothing.
	if r.failed.Load() && !r.scanned.Load() {
		if !r.Options.Verbose {
			return fmt.Errorf("%w (use -v to see why)", ErrAllTargetsFailed)
		}

		return ErrAllTargetsFailed
	}

	return nil
}

func pushInput(r *Runner) {
	defer r.InWg.Done()

	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			pushTarget(r, scanner.Text())
		}
	}

	if r.Options.FileInput != "" {
		for _, line := range golazy.RemoveDuplicateValues(golazy.ReadFileLineByLine(r.Options.FileInput)) {
			pushTarget(r, line)
		}
	}

	if r.Options.Input != "" {
		pushTarget(r, r.Options.Input)
	}

	close(r.Input)
}

// pushTarget queues one input value. With -cidr the value is a range, and its
// addresses are queued as they are generated: scanning starts right away and
// memory stays flat however large the range is.
func pushTarget(r *Runner, value string) {
	if !r.Options.Cidr {
		r.Input <- value

		return
	}

	ips, err := handleCIDRInput(value)
	if err != nil {
		r.failed.Store(true)
		gologger.Error().Msg(err.Error())

		return
	}

	for ip := range ips {
		r.Input <- ip
	}
}

func execute(r *Runner) {
	defer r.InWg.Done()

	dregex := CompileRegex(DomainRegex)
	rl := rateLimiter(r)
	bypass := bypassEnabled(&r.Options)

	for i := 0; i < r.Options.Concurrency; i++ {
		r.InWg.Add(1)

		go func() {
			defer r.InWg.Done()

			for value := range r.Input {
				targetURL, err := PrepareURL(value)
				if err != nil {
					r.failed.Store(true)
					gologger.Error().Msgf("%s", err)

					continue
				}

				rl.Take()

				csp, err := checkCSPFull(targetURL, r.UserAgent, dregex, r.client, bypass)
				if err != nil {
					r.failed.Store(true)

					// An unreachable target does not stop the run. gologger
					// ranks Warning below Info, so this shows only with -v.
					gologger.Warning().Msgf("%s", err)

					continue
				}

				r.scanned.Store(true)

				var findings []bypassFinding
				if bypass && r.gadgets != nil {
					// 'self' and scheme-less sources refer to the page the CSP
					// came from, which differs from targetURL after a redirect.
					findings = r.gadgets.bypasses(targetURL, cmp.Or(csp.FinalURL, targetURL), csp.Enforced)
				}

				if r.Options.JSON {
					sendJSON(r, targetURL, csp, findings)
				} else {
					sendPlain(r, targetURL, csp.Domains, findings)
				}
			}
		}()
	}
}

// sendJSON queues the JSON record of one target.
func sendJSON(r *Runner, targetURL string, csp cspData, findings []bypassFinding) {
	domains := csp.Domains
	if len(r.Options.Domain) != 0 {
		domains = filterDomains(domains, r.Options.Domain)
	}

	data := output.JSONData{URL: targetURL, FinalURL: csp.FinalURL, CSPResult: domains}
	if len(findings) != 0 {
		data.Bypasses = toBypassResults(findings)
	}

	out, err := output.FormatJSON(data)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	r.Output <- string(out)
}

// sendPlain queues the plain-text lines of one target, together so that they
// are printed together. Each domain is printed once per run.
func sendPlain(r *Runner, targetURL string, domains []string, findings []bypassFinding) {
	var lines []string

	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || (len(r.Options.Domain) != 0 && !DomainOk(d, r.Options.Domain)) {
			continue
		}

		if !r.Result.Printed(d) {
			lines = append(lines, d)
		}
	}

	// A bypass line names its target, so it can only repeat when a target is
	// given twice (e.g. as a.com and http://a.com). Remembering the target
	// instead of every line keeps memory small: one target can have hundreds
	// of bypass lines.
	if len(findings) != 0 && !r.Result.Printed(BypassPrefix+" "+targetURL) {
		for _, f := range findings {
			lines = append(lines, formatBypassLine(f))
		}
	}

	if len(lines) != 0 {
		r.Output <- strings.Join(lines, "\n")
	}
}

// pullOutput is the only writer: lines come out whole and in the order they
// were queued, and a slow reader slows the workers down instead of piling up
// goroutines.
func pullOutput(r *Runner) {
	defer r.OutWg.Done()

	for line := range r.Output {
		if r.outFile != nil {
			// Stop at once: a results file with lines missing must not look
			// complete.
			if _, err := r.outFile.WriteString(line + "\n"); err != nil {
				gologger.Fatal().Msgf("output file: %s", err)
			}
		}

		if r.color {
			line = highlightBypass(line)
		}

		fmt.Println(line)
	}
}

// highlightBypass colors the label of every bypass line in a block of plain
// lines. Bold bright green is used by no gologger label, so a finding never
// looks like a log message. Lines never contain a newline, so a bypass line is
// a prefix found at the start of the block or after a "\n".
func highlightBypass(block string) string {
	plain := "\n" + BypassPrefix + " "
	colored := "\n[" + aurora.Bold(aurora.BrightGreen(bypassLabel)).String() + "] "

	return strings.ReplaceAll("\n"+block, plain, colored)[1:]
}

// filterDomains keeps only the domains belonging to one of the allowed domains.
func filterDomains(domains, allowed []string) []string {
	filtered := []string{}

	for _, d := range domains {
		if DomainOk(d, allowed) {
			filtered = append(filtered, d)
		}
	}

	return filtered
}
