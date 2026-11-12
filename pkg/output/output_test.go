/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package output_test

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/edoardottt/csprecon/pkg/output"

	"github.com/stretchr/testify/require"
)

func TestResultPrinted(t *testing.T) {
	t.Parallel()

	r := output.New()

	require.False(t, r.Printed("a.example")) // first time: not yet printed
	require.True(t, r.Printed("a.example"))  // second time: already printed
	require.False(t, r.Printed("b.example")) // distinct key
	require.True(t, r.Printed("b.example"))
	require.False(t, r.Printed("")) // empty string is still a valid key
	require.True(t, r.Printed(""))
}

// TestResultPrintedConcurrent hammers Printed from many goroutines to ensure the
// dedup map is race-free and that exactly one caller sees each key as new.
func TestResultPrintedConcurrent(t *testing.T) {
	t.Parallel()

	const (
		keys       = 50
		goroutines = 40
	)

	r := output.New()

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		firsts  = map[string]int{} // how many goroutines saw each key as "new"
		starter = make(chan struct{})
	)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-starter // release all at once to maximise contention

			for k := 0; k < keys; k++ {
				key := strconv.Itoa(k)
				if !r.Printed(key) {
					mu.Lock()
					firsts[key]++
					mu.Unlock()
				}
			}
		}()
	}

	close(starter)
	wg.Wait()

	require.Len(t, firsts, keys)

	for k := 0; k < keys; k++ {
		require.Equal(t, 1, firsts[strconv.Itoa(k)], "key %d should be new exactly once", k)
	}
}

func TestFormatJSON(t *testing.T) {
	t.Parallel()

	t.Run("with bypasses", func(t *testing.T) {
		t.Parallel()

		data := output.JSONData{
			URL:       "https://victim.example",
			CSPResult: []string{"a.example", "b.example"},
			Bypasses: []output.BypassResult{{
				Domain:    "a.example",
				Directive: "script-src",
				Code:      "<script></script>",
				Flags:     []string{"unsafe-inline"},
			}},
		}

		out, err := output.FormatJSON(data)
		require.NoError(t, err)

		var round output.JSONData
		require.NoError(t, json.Unmarshal(out, &round))
		require.Equal(t, data.URL, round.URL)
		require.Equal(t, data.CSPResult, round.CSPResult)
		require.Len(t, round.Bypasses, 1)
		require.Equal(t, "a.example", round.Bypasses[0].Domain)
	})

	t.Run("omits empty optional fields", func(t *testing.T) {
		t.Parallel()

		out, err := output.FormatJSON(output.JSONData{URL: "https://victim.example"})
		require.NoError(t, err)
		require.NotContains(t, string(out), "CSPResult")
		require.NotContains(t, string(out), "Bypasses")
	})

	t.Run("escapes html in code", func(t *testing.T) {
		t.Parallel()

		data := output.JSONData{
			URL:      "https://victim.example",
			Bypasses: []output.BypassResult{{Domain: "a.example", Code: `<script src="x">`}},
		}

		out, err := output.FormatJSON(data)
		require.NoError(t, err)

		// Still round-trips to the exact original string.
		var round output.JSONData
		require.NoError(t, json.Unmarshal(out, &round))
		require.Equal(t, `<script src="x">`, round.Bypasses[0].Code)
	})
}
