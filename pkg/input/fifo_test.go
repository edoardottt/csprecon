//go:build linux || darwin

/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package input_test

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// A named pipe stands in for process substitution (-bf <(curl ...)), which must
// keep being accepted: only directories are rejected. Validation must not open
// it either, as opening a pipe with no writer blocks.
func TestValidateOptionsAcceptsFIFO(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "data.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	o := baseValidOptions()
	o.BypassFile = fifo

	require.NoError(t, o.ValidateOptions())

	o = baseValidOptions()
	o.FileInput = fifo

	require.NoError(t, o.ValidateOptions(), "-l <(cmd) must keep working too")

	// Writing results into a pipe, e.g. -o >(cmd), must keep working as well.
	o = baseValidOptions()
	o.FileOutput = fifo

	require.NoError(t, o.ValidateOptions())
}
