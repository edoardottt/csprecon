/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/csprecon/pkg/output"

	"github.com/stretchr/testify/require"
)

const (
	runnerTargets     = 30
	runnerConcurrency = 16
	runnerTimeout     = 10
)

const gadgetTSV = "Domain\tCode\n" +
	"gadget.example\t<script src=\"https://gadget.example/jsonp?cb=alert(1)\"></script>\n" +
	"imgonly.example\t<script src=\"https://imgonly.example/jsonp?cb=alert(1)\"></script>\n"

func cspHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Security-Policy",
		"script-src 'self' https://gadget.example; img-src https://imgonly.example")
	_, _ = io.WriteString(w, "<html></html>")
}

// cspServer returns an HTTP server that whitelists gadget.example for scripts
// and imgonly.example only for images (so imgonly must never be a bypass).
func cspServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(cspHandler))

	t.Cleanup(srv.Close)

	return srv
}

// targetListFile writes runnerTargets distinct URLs (distinct paths) to a file.
func targetListFile(t *testing.T, base string) string {
	t.Helper()

	return targetListFileN(t, base, runnerTargets)
}

// targetListFileN writes n distinct URLs (distinct paths) to a file.
func targetListFileN(t *testing.T, base string, n int) string {
	t.Helper()

	var sb strings.Builder

	for i := 0; i < n; i++ {
		_, _ = fmt.Fprintf(&sb, "%s/p%d\n", base, i)
	}

	path := filepath.Join(t.TempDir(), "targets.txt")
	require.NoError(t, os.WriteFile(path, []byte(sb.String()), 0o600))

	return path
}

func gadgetFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "gadgets.tsv")
	require.NoError(t, os.WriteFile(path, []byte(gadgetTSV), 0o600))

	return path
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. fn must return before captureStdout does.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout

	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	outC := make(chan string, 1)

	go func() {
		var sb strings.Builder

		_, _ = io.Copy(&sb, r)
		outC <- sb.String()
	}()

	fn()

	require.NoError(t, w.Close())

	os.Stdout = old

	return <-outC
}

// runRunner runs a Runner to completion and requires it to succeed.
func runRunner(t *testing.T, opts *input.Options) string {
	t.Helper()

	out, err := runRunnerErr(t, opts)
	require.NoError(t, err)

	return out
}

// runRunnerErr runs a Runner to completion with a safety timeout and returns
// its stdout and the error Run returned.
func runRunnerErr(t *testing.T, opts *input.Options) (string, error) {
	t.Helper()

	var (
		out    string
		runErr error
	)

	done := make(chan struct{})

	go func() {
		out = captureStdout(t, func() {
			runner := csprecon.New(opts)
			runErr = runner.Run()
		})

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("runner did not finish within 30s")
	}

	return out, runErr
}

func nonEmptyLines(s string) []string {
	var lines []string

	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}

	return lines
}

// TestRunnerPlainBypassConcurrent drives the full concurrent pipeline in plain
// mode with the bypass feature enabled. Run with -race to catch data races on
// the shared gadget DB, channels and dedup map.
func TestRunnerPlainBypassConcurrent(t *testing.T) {
	srv := cspServer(t)

	opts := &input.Options{
		FileInput:   targetListFile(t, srv.URL),
		BypassFile:  gadgetFile(t),
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		Silent:      true,
	}

	out := runRunner(t, opts)
	lines := nonEmptyLines(out)

	var bypassLines []string

	for _, l := range lines {
		if strings.HasPrefix(l, csprecon.BypassPrefix+" ") {
			bypassLines = append(bypassLines, l)
			require.Contains(t, l, "gadget.example")
			require.Contains(t, l, "script-src")
			require.NotContains(t, l, "imgonly.example")
		}
	}

	// One bypass line per distinct target URL.
	require.Len(t, bypassLines, runnerTargets)

	// Domains are discovered (and de-duplicated) regardless of bypass.
	require.Contains(t, lines, "gadget.example")
	require.Contains(t, lines, "imgonly.example")
}

// TestRunnerJSONBypassConcurrent drives the pipeline in JSON mode.
func TestRunnerJSONBypassConcurrent(t *testing.T) {
	srv := cspServer(t)

	opts := &input.Options{
		FileInput:   targetListFile(t, srv.URL),
		BypassFile:  gadgetFile(t),
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		JSON:        true,
		Silent:      true,
	}

	out := runRunner(t, opts)
	lines := nonEmptyLines(out)

	require.Len(t, lines, runnerTargets)

	for _, l := range lines {
		var record output.JSONData

		require.NoError(t, json.Unmarshal([]byte(l), &record), "line: %s", l)
		require.NotEmpty(t, record.URL)
		require.Contains(t, record.CSPResult, "gadget.example")
		require.Contains(t, record.CSPResult, "imgonly.example")
		require.Len(t, record.Bypasses, 1)
		require.Equal(t, "gadget.example", record.Bypasses[0].Domain)
		require.Equal(t, "script-src", record.Bypasses[0].Directive)
		require.Empty(t, record.FinalURL, "no redirect, so no final URL")
	}
}

// TestRunnerRedirectedTarget checks that bypasses are evaluated against the page
// a target redirects to: there 'self' means the final origin, so only the
// gadget on the final server is a bypass, reported under the input URL.
func TestRunnerRedirectedTarget(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self'")
	}))
	t.Cleanup(final.Close)

	start := httptest.NewServer(http.RedirectHandler(final.URL+"/landing", http.StatusFound))
	t.Cleanup(start.Close)

	gadgets := filepath.Join(t.TempDir(), "gadgets.tsv")
	require.NoError(t, os.WriteFile(gadgets, []byte("Domain\tCode\n"+
		"127.0.0.1\t<script src=\""+start.URL+"/jsonp?cb=start\"></script>\n"+
		"127.0.0.1\t<script src=\""+final.URL+"/jsonp?cb=final\"></script>\n"), 0o600))

	target := start.URL + "/go"

	t.Run("plain", func(t *testing.T) {
		out := runRunner(t, &input.Options{
			Input: target, BypassFile: gadgets, Concurrency: 1, Timeout: runnerTimeout, Silent: true,
		})

		lines := nonEmptyLines(out)
		require.Len(t, lines, 1, "output: %q", out)
		require.True(t, strings.HasPrefix(lines[0], csprecon.BypassPrefix+" "+target+" 127.0.0.1 script-src "))
		require.Contains(t, lines[0], "cb=final")
	})

	t.Run("json", func(t *testing.T) {
		out := runRunner(t, &input.Options{
			Input: target, BypassFile: gadgets, Concurrency: 1, Timeout: runnerTimeout, Silent: true, JSON: true,
		})

		var record output.JSONData

		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &record), "output: %q", out)
		require.Equal(t, target, record.URL)
		require.Equal(t, final.URL+"/landing", record.FinalURL)
		require.Len(t, record.Bypasses, 1)
		require.Contains(t, record.Bypasses[0].Code, "cb=final")
	})
}

// TestRunnerFileOutputConcurrent writes results to a file under concurrency.
// Run with -race to guard against the writers racing on the shared output
// handle.
func TestRunnerFileOutputConcurrent(t *testing.T) {
	srv := cspServer(t)
	outFile := filepath.Join(t.TempDir(), "out.txt")

	opts := &input.Options{
		FileInput:   targetListFile(t, srv.URL),
		FileOutput:  outFile,
		BypassFile:  gadgetFile(t),
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		Silent:      true,
	}

	out := runRunner(t, opts)

	content, err := os.ReadFile(outFile)
	require.NoError(t, err)

	// One writer prints every line to both, in the same order.
	require.Equal(t, out, string(content))

	lines := nonEmptyLines(string(content))

	var bypassLines int

	for _, l := range lines {
		if strings.HasPrefix(l, csprecon.BypassPrefix+" ") {
			bypassLines++

			require.Contains(t, l, "gadget.example")
			require.NotContains(t, l, "imgonly.example")
		}
	}

	require.Equal(t, runnerTargets, bypassLines)
	require.Contains(t, lines, "gadget.example")
	require.Contains(t, lines, "imgonly.example")
}

// TestRunnerNoCSPTarget ensures a target without CSP produces no output and does
// not crash the pipeline.
func TestRunnerNoCSPTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html><body>no csp here</body></html>")
	}))
	t.Cleanup(srv.Close)

	opts := &input.Options{
		Input:       srv.URL,
		BypassFile:  gadgetFile(t),
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		Silent:      true,
	}

	out := runRunner(t, opts)
	require.Empty(t, nonEmptyLines(out))
}

// connCounter records the connections a test server accepts and how many of
// them are still open.
type connCounter struct {
	mu       sync.Mutex
	accepted int
	open     map[net.Conn]struct{}
}

func (c *connCounter) track(conn net.Conn, state http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch state { //nolint:exhaustive // only the lifecycle edges matter.
	case http.StateNew:
		c.accepted++
		c.open[conn] = struct{}{}
	case http.StateClosed, http.StateHijacked:
		delete(c.open, conn)
	}
}

func (c *connCounter) counts() (accepted, open int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.accepted, len(c.open)
}

// TestRunnerReusesConnections checks that the workers share one HTTP client:
// many same-host HTTPS targets are served over a few reused connections instead
// of one new connection (and TLS handshake) each, and the pooled connections are
// closed once the run is over instead of lingering until the idle timeout.
func TestRunnerReusesConnections(t *testing.T) {
	const (
		targets     = 60
		concurrency = 4
	)

	counter := &connCounter{open: map[net.Conn]struct{}{}}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(cspHandler))
	srv.Config.ConnState = counter.track
	srv.StartTLS()
	t.Cleanup(srv.Close)

	opts := &input.Options{
		FileInput:   targetListFileN(t, srv.URL, targets),
		BypassFile:  gadgetFile(t),
		Concurrency: concurrency,
		Timeout:     runnerTimeout,
		JSON:        true,
		Silent:      true,
	}

	lines := nonEmptyLines(runRunner(t, opts))
	require.Len(t, lines, targets, "every target must still be scanned")

	accepted, _ := counter.counts()
	t.Logf("%d targets served over %d connections", targets, accepted)
	require.Less(t, accepted, targets/2, "connections are not being reused")

	require.Eventually(t, func() bool {
		_, open := counter.counts()

		return open == 0
	}, 5*time.Second, 10*time.Millisecond, "idle connections left open after Run")
}

// TestRunnerUsesProxy checks that the shared client still routes every request
// through the configured proxy.
func TestRunnerUsesProxy(t *testing.T) {
	var (
		mu    sync.Mutex
		hosts []string
	)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()

		hosts = append(hosts, r.URL.Host)

		mu.Unlock()

		w.Header().Set("Content-Security-Policy", "script-src https://viaproxy.example")
	}))
	t.Cleanup(proxy.Close)

	opts := &input.Options{
		Input:       "http://target.invalid/x",
		Proxy:       proxy.URL,
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		Silent:      true,
	}

	out := runRunner(t, opts)
	require.Equal(t, []string{"viaproxy.example"}, nonEmptyLines(out))

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, []string{"target.invalid"}, hosts)
}

// TestRunnerJSONFileOutput checks that JSON records reach the file whole and
// in the order they are printed.
func TestRunnerJSONFileOutput(t *testing.T) {
	srv := cspServer(t)
	outFile := filepath.Join(t.TempDir(), "out.json")

	out := runRunner(t, &input.Options{
		FileInput:   targetListFile(t, srv.URL),
		FileOutput:  outFile,
		BypassFile:  gadgetFile(t),
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		JSON:        true,
		Silent:      true,
	})

	content, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.Equal(t, out, string(content))

	lines := nonEmptyLines(string(content))
	require.Len(t, lines, runnerTargets)

	for _, l := range lines {
		var record output.JSONData

		require.NoError(t, json.Unmarshal([]byte(l), &record), "line: %s", l)
		require.Len(t, record.Bypasses, 1)
	}
}

// TestRunnerOutputFileTruncated checks that -o replaces what the file held.
func TestRunnerOutputFileTruncated(t *testing.T) {
	srv := cspServer(t)
	outFile := filepath.Join(t.TempDir(), "out.txt")
	require.NoError(t, os.WriteFile(outFile, []byte(strings.Repeat("stale line\n", 1000)), 0o600))

	out := runRunner(t, &input.Options{
		Input: srv.URL, FileOutput: outFile, Concurrency: 1, Timeout: runnerTimeout, Silent: true,
	})

	content, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.Equal(t, out, string(content))
	require.NotContains(t, string(content), "stale")
}

// TestRunnerDuplicateTarget checks that a target given twice in different
// spellings reports its bypasses once, while distinct targets on the same
// host each report theirs.
func TestRunnerDuplicateTarget(t *testing.T) {
	srv := cspServer(t)
	hostPort := strings.TrimPrefix(srv.URL, "http://")

	list := filepath.Join(t.TempDir(), "targets.txt")
	require.NoError(t, os.WriteFile(list, []byte(
		srv.URL+"\n"+hostPort+"\n"+srv.URL+"/other\n"+hostPort+"/other\n"), 0o600))

	for _, concurrency := range []int{1, runnerConcurrency} {
		out := runRunner(t, &input.Options{
			FileInput: list, BypassFile: gadgetFile(t), Concurrency: concurrency, Timeout: runnerTimeout, Silent: true,
		})

		var bypassLines []string

		for _, l := range nonEmptyLines(out) {
			if strings.HasPrefix(l, csprecon.BypassPrefix+" ") {
				bypassLines = append(bypassLines, l)
			}
		}

		require.ElementsMatch(t, []string{
			csprecon.BypassPrefix + " " + srv.URL + " gadget.example script-src " +
				`<script src="https://gadget.example/jsonp?cb=alert(1)"></script>`,
			csprecon.BypassPrefix + " " + srv.URL + "/other gadget.example script-src " +
				`<script src="https://gadget.example/jsonp?cb=alert(1)"></script>`,
		}, bypassLines, "concurrency %d", concurrency)

		require.Len(t, nonEmptyLines(out), len(bypassLines)+2, "each domain is printed once")
	}
}

// deadURL returns the URL of a server that is already closed, so every
// request to it fails.
func deadURL(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	return srv.URL
}

// TestRunnerFailures checks that Run fails only when not a single target
// could be scanned, and that a failure never hides the results.
func TestRunnerFailures(t *testing.T) {
	srv := cspServer(t)
	dead := deadURL(t)

	noCSP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(noCSP.Close)

	listOf := func(t *testing.T, lines ...string) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "targets.txt")
		require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

		return path
	}

	tests := []struct {
		name    string
		opts    input.Options
		wantErr bool
		want    []string
	}{
		{
			name:    "unreachable target",
			opts:    input.Options{Input: dead},
			wantErr: true,
		},
		{
			name:    "every target unreachable",
			opts:    input.Options{FileInput: listOf(t, dead+"/a", dead+"/b", dead+"/c")},
			wantErr: true,
		},
		{
			name:    "malformed target",
			opts:    input.Options{Input: "a"},
			wantErr: true,
		},
		{
			name:    "malformed CIDR",
			opts:    input.Options{Input: "10.0.0.0/33", Cidr: true},
			wantErr: true,
		},
		{
			name: "one target reachable",
			opts: input.Options{FileInput: listOf(t, dead+"/a", srv.URL, dead+"/b")},
			want: []string{"gadget.example", "imgonly.example"},
		},
		{
			name: "target without a CSP is not a failure",
			opts: input.Options{Input: noCSP.URL},
		},
		{
			name: "error status is not a failure",
			opts: input.Options{Input: noCSP.URL + "/missing"},
		},
		{
			name: "results filtered out by -d are not a failure",
			opts: input.Options{Input: srv.URL, Domain: []string{"nomatch.example"}},
		},
		{
			name: "empty list",
			opts: input.Options{FileInput: listOf(t)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, verbose := range []bool{false, true} {
				opts := tt.opts
				opts.Concurrency = runnerConcurrency
				opts.Timeout = runnerTimeout
				opts.Silent = !verbose
				opts.Verbose = verbose

				out, err := runRunnerErr(t, &opts)
				require.ElementsMatch(t, tt.want, nonEmptyLines(out))

				if !tt.wantErr {
					require.NoError(t, err)

					continue
				}

				require.ErrorIs(t, err, csprecon.ErrAllTargetsFailed)

				if verbose {
					require.Equal(t, csprecon.ErrAllTargetsFailed.Error(), err.Error(), "the errors were already shown")
				} else {
					require.ErrorContains(t, err, "-v")
				}
			}
		})
	}
}

// fatalChildEnv tells a test binary to run a fatal scenario in place of a
// test; it is how the tests below observe the process exiting.
const fatalChildEnv = "CSPRECON_FATAL_CHILD"

// runFatalChild runs scenario in a child test process and returns its exit
// code and stderr.
func runFatalChild(t *testing.T, scenario string, env ...string) (int, string) {
	t.Helper()

	var stderr strings.Builder

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerFatal$")
	cmd.Stderr = &stderr

	cmd.Env = append(os.Environ(), fatalChildEnv+"="+scenario)
	cmd.Env = append(cmd.Env, env...)

	err := cmd.Run()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stderr.String()
	}

	require.NoError(t, err, "stderr: %s", stderr.String())

	return 0, stderr.String()
}

// fatalChild runs one scenario that must end the process. It returns only if
// the process did not exit, which the parent sees as exit code 0.
func fatalChild(t *testing.T, scenario string) {
	t.Helper()

	srv := cspServer(t)
	opts := &input.Options{Input: srv.URL, Concurrency: 1, Timeout: runnerTimeout, Silent: true}

	switch scenario {
	case "write":
		opts.FileOutput = "/dev/full"
	case "open":
		opts.FileOutput = os.Getenv("OUT_FILE")
	case "gadgets":
		opts.FileOutput = os.Getenv("OUT_FILE")
		opts.Bypass = true

		csprecon.SetBypassDataURL(deadURL(t))
		csprecon.SetCachePathFunc(func() (string, error) {
			return filepath.Join(t.TempDir(), "no-cache.tsv"), nil
		})
	}

	runner := csprecon.New(opts)
	_ = runner.Run()
}

// TestRunnerFatal checks the I/O problems that must stop the run with exit
// code 1 instead of leaving incomplete or wiped results behind.
func TestRunnerFatal(t *testing.T) {
	if scenario := os.Getenv(fatalChildEnv); scenario != "" {
		fatalChild(t, scenario)

		return
	}

	t.Run("write error", func(t *testing.T) {
		if _, err := os.Stat("/dev/full"); err != nil {
			t.Skip("no /dev/full")
		}

		code, stderr := runFatalChild(t, "write")
		require.Equal(t, 1, code, "stderr: %s", stderr)
		require.Contains(t, stderr, "output file: write /dev/full: no space left on device")
	})

	t.Run("output file cannot be opened", func(t *testing.T) {
		notDir := filepath.Join(t.TempDir(), "file.txt")
		require.NoError(t, os.WriteFile(notDir, nil, 0o600))

		code, stderr := runFatalChild(t, "open", "OUT_FILE="+filepath.Join(notDir, "out.txt"))
		require.Equal(t, 1, code, "stderr: %s", stderr)
		require.Contains(t, stderr, "output file: open ")
	})

	t.Run("failed gadget load keeps the old results", func(t *testing.T) {
		outFile := filepath.Join(t.TempDir(), "out.txt")
		require.NoError(t, os.WriteFile(outFile, []byte("previous results\n"), 0o600))

		code, stderr := runFatalChild(t, "gadgets", "OUT_FILE="+outFile)
		require.Equal(t, 1, code, "stderr: %s", stderr)
		require.Contains(t, stderr, "bypass: ")

		content, err := os.ReadFile(outFile)
		require.NoError(t, err)
		require.Equal(t, "previous results\n", string(content))
	})

	t.Run("failed gadget load creates no output file", func(t *testing.T) {
		outFile := filepath.Join(t.TempDir(), "out.txt")

		code, stderr := runFatalChild(t, "gadgets", "OUT_FILE="+outFile)
		require.Equal(t, 1, code, "stderr: %s", stderr)
		require.NoFileExists(t, outFile)
	})
}

// TestRunnerTargetLinesTogether checks that the lines of one target are
// printed together, not mixed with those of targets scanned at the same time.
func TestRunnerTargetLinesTogether(t *testing.T) {
	const gadgets = 50

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src https:; img-src https://img.example")
	}))
	t.Cleanup(srv.Close)

	var tsv strings.Builder

	tsv.WriteString("Domain\tCode\n")

	for i := range gadgets {
		_, _ = fmt.Fprintf(&tsv, "g%d.example\t<script src=\"https://g%d.example/x?cb=alert\"></script>\n", i, i)
	}

	gadgetPath := filepath.Join(t.TempDir(), "gadgets.tsv")
	require.NoError(t, os.WriteFile(gadgetPath, []byte(tsv.String()), 0o600))

	out := runRunner(t, &input.Options{
		FileInput:   targetListFile(t, srv.URL),
		BypassFile:  gadgetPath,
		Concurrency: runnerConcurrency,
		Timeout:     runnerTimeout,
		Silent:      true,
	})

	lines := nonEmptyLines(out)
	require.Len(t, lines, runnerTargets*gadgets+1)
	require.Contains(t, lines, "img.example")

	var targets []string

	for _, l := range lines {
		if fields := strings.Fields(l); len(fields) > 1 && fields[0] == csprecon.BypassPrefix &&
			(len(targets) == 0 || targets[len(targets)-1] != fields[1]) {
			targets = append(targets, fields[1])
		}
	}

	require.Len(t, targets, runnerTargets, "a target's lines were split up")
}

// TestRunnerDomains checks the domains a target reports, in plain and JSON
// output, with and without -d: hosts only, each once, although the policy is
// sent in two headers and a meta tag.
func TestRunnerDomains(t *testing.T) {
	const policy = "script-src https://CDN.example.com/js/app.min.js https://cdn.example.com:443; " +
		"report-uri /csp/report.php; img-src https://img.example.org/a.png"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("Content-Security-Policy-Report-Only", policy)
		_, _ = io.WriteString(w, `<html><head><meta http-equiv="Content-Security-Policy" content="`+policy+`"></head></html>`)
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name   string
		domain []string
		want   []string
	}{
		{name: "all", want: []string{"cdn.example.com", "img.example.org"}},
		{name: "filtered", domain: []string{"EXAMPLE.com"}, want: []string{"cdn.example.com"}},
		{name: "nothing left", domain: []string{"other.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := input.Options{Input: srv.URL, Domain: tt.domain, Concurrency: 1, Timeout: runnerTimeout, Silent: true}

			plain := runRunner(t, &opts)
			require.Equal(t, tt.want, nonEmptyLines(plain))

			opts.JSON = true

			var record output.JSONData

			require.NoError(t, json.Unmarshal([]byte(runRunner(t, &opts)), &record))
			require.Equal(t, tt.want, record.CSPResult)
		})
	}
}

// TestRunnerSharedDomains checks a domain found on two targets: plain output
// prints it once, while each target's JSON record lists it. -o must hold the
// same as stdout in both modes.
func TestRunnerSharedDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"script-src https://cdn.example.com/app.js https://shared.example.org; img-src https://cdn.example.com")
	}))
	t.Cleanup(srv.Close)

	want := []string{"cdn.example.com", "shared.example.org"}
	url1, url2 := srv.URL+"/url1", srv.URL+"/url2"

	list := filepath.Join(t.TempDir(), "targets.txt")
	require.NoError(t, os.WriteFile(list, []byte(url1+"\n"+url2+"\n"), 0o600))

	for _, concurrency := range []int{1, runnerConcurrency} {
		t.Run(fmt.Sprintf("concurrency %d", concurrency), func(t *testing.T) {
			outFile := filepath.Join(t.TempDir(), "out")
			opts := input.Options{
				FileInput: list, FileOutput: outFile, Concurrency: concurrency, Timeout: runnerTimeout, Silent: true,
			}

			plain := runRunner(t, &opts)
			require.Equal(t, want, nonEmptyLines(plain))

			content, err := os.ReadFile(outFile)
			require.NoError(t, err)
			require.Equal(t, plain, string(content))

			opts.JSON = true
			out := runRunner(t, &opts)

			content, err = os.ReadFile(outFile)
			require.NoError(t, err)
			require.Equal(t, out, string(content))

			records := map[string][]string{}

			for _, l := range nonEmptyLines(out) {
				var record output.JSONData

				require.NoError(t, json.Unmarshal([]byte(l), &record), "line: %s", l)
				records[record.URL] = record.CSPResult
			}

			require.Equal(t, map[string][]string{url1: want, url2: want}, records)
		})
	}
}
