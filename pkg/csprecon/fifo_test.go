//go:build linux || darwin

/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"

	"github.com/stretchr/testify/require"
)

// TestLoadGadgetsFromFIFO checks that a named pipe, as produced by process
// substitution (-bf <(curl ...)), is still read as a dataset.
func TestLoadGadgetsFromFIFO(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "data.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	writeErr := make(chan error, 1)

	go func() {
		// Opening a FIFO for writing blocks until the reader opens it.
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			writeErr <- err

			return
		}

		_, err = f.WriteString("Domain\tCode\nx.example\t<script src=\"https://x.example/a\"></script>\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}

		writeErr <- err
	}()

	type result struct {
		db  *csprecon.GadgetDB
		src string
		err error
	}

	done := make(chan result, 1)

	go func() {
		db, src, err := csprecon.LoadGadgetsForTest(&input.Options{BypassFile: fifo})
		done <- result{db, src, err}
	}()

	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, "file", r.src)
		require.Len(t, csprecon.GadgetEntries(r.db), 1)
	case <-time.After(10 * time.Second):
		t.Fatal("reading the FIFO did not finish")
	}

	require.NoError(t, <-writeErr)
}
