/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package input_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/edoardottt/csprecon/pkg/input"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/stretchr/testify/require"
)

const (
	validConcurrency = 50
	validTimeout     = 10
)

func baseValidOptions() *input.Options {
	return &input.Options{
		Input:       "example.com",
		Concurrency: validConcurrency,
		Timeout:     validTimeout,
	}
}

// tempFile creates a file with some content and returns its path.
func tempFile(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte("example.com\n"), 0o600))

	return path
}

func TestValidateOptions(t *testing.T) {
	t.Parallel()

	t.Run("valid options", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, baseValidOptions().ValidateOptions())
	})

	t.Run("silent and verbose are mutually exclusive", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Silent = true
		o.Verbose = true

		require.ErrorIs(t, o.ValidateOptions(), input.ErrMutexFlags)
	})

	t.Run("zero concurrency is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Concurrency = 0

		require.ErrorIs(t, o.ValidateOptions(), input.ErrNegativeValue)
	})

	t.Run("negative concurrency is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Concurrency = -1

		require.ErrorIs(t, o.ValidateOptions(), input.ErrNegativeValue)
	})

	t.Run("negative rate limit is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.RateLimit = -5

		require.ErrorIs(t, o.ValidateOptions(), input.ErrNegativeValue)
	})

	t.Run("zero timeout is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Timeout = 0

		err := o.ValidateOptions()
		require.ErrorIs(t, err, input.ErrNegativeValue)
		require.ErrorContains(t, err, "timeout")
	})

	t.Run("negative timeout is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Timeout = -1

		require.ErrorIs(t, o.ValidateOptions(), input.ErrNegativeValue)
	})

	t.Run("malformed proxy is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Proxy = "http://%zz"

		require.ErrorIs(t, o.ValidateOptions(), input.ErrBadProxy)
	})

	t.Run("proxy without a scheme is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.Proxy = "localhost:8080"

		err := o.ValidateOptions()
		require.ErrorIs(t, err, input.ErrBadProxy)
		require.ErrorContains(t, err, "localhost:8080")
	})

	t.Run("missing bypass file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.BypassFile = filepath.Join(t.TempDir(), "does-not-exist.tsv")

		err := o.ValidateOptions()
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.ErrorContains(t, err, "bypass file")
	})

	t.Run("existing bypass file is accepted", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "data.tsv")
		require.NoError(t, os.WriteFile(path, []byte("Domain\tCode\n"), 0o600))

		o := baseValidOptions()
		o.BypassFile = path

		require.NoError(t, o.ValidateOptions())
	})

	t.Run("directory bypass file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.BypassFile = t.TempDir()

		err := o.ValidateOptions()
		require.ErrorIs(t, err, input.ErrIsDirectory)
		require.NotErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("no input is rejected", func(t *testing.T) {
		t.Parallel()

		if fileutil.HasStdin() {
			t.Skip("stdin is attached; no-input path not reachable")
		}

		o := &input.Options{Concurrency: validConcurrency}

		require.ErrorIs(t, o.ValidateOptions(), input.ErrNoInput)
	})
}

func TestValidateListFile(t *testing.T) {
	t.Parallel()

	t.Run("existing list file is accepted", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileInput = tempFile(t, "targets.txt")

		require.NoError(t, o.ValidateOptions())
	})

	t.Run("missing list file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileInput = filepath.Join(t.TempDir(), "nope.txt")

		err := o.ValidateOptions()
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.ErrorContains(t, err, "list file")
	})

	t.Run("directory list file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileInput = t.TempDir()

		require.ErrorIs(t, o.ValidateOptions(), input.ErrIsDirectory)
	})

	t.Run("unreadable list file is rejected", func(t *testing.T) {
		t.Parallel()

		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("file modes do not restrict this user")
		}

		path := tempFile(t, "targets.txt")
		require.NoError(t, os.Chmod(path, 0))

		o := baseValidOptions()
		o.FileInput = path

		require.ErrorIs(t, o.ValidateOptions(), fs.ErrPermission)
	})
}

func TestValidateOutputFile(t *testing.T) {
	t.Parallel()

	t.Run("new file in an existing directory is accepted and not created", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileOutput = filepath.Join(t.TempDir(), "out.txt")

		require.NoError(t, o.ValidateOptions())
		require.NoFileExists(t, o.FileOutput, "validation must not create the file")
	})

	t.Run("existing file is accepted and left untouched", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileOutput = tempFile(t, "out.txt")

		require.NoError(t, o.ValidateOptions())

		content, err := os.ReadFile(o.FileOutput)
		require.NoError(t, err)
		require.Equal(t, "example.com\n", string(content))
	})

	t.Run("directory is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileOutput = t.TempDir()

		err := o.ValidateOptions()
		require.ErrorIs(t, err, input.ErrIsDirectory)
		require.ErrorContains(t, err, "output file")
	})

	t.Run("missing directory is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileOutput = filepath.Join(t.TempDir(), "nope", "out.txt")

		require.ErrorIs(t, o.ValidateOptions(), fs.ErrNotExist)
	})

	t.Run("file used as a directory is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileOutput = filepath.Join(tempFile(t, "file.txt"), "out.txt")

		require.Error(t, o.ValidateOptions())
	})

	t.Run("list file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileInput = tempFile(t, "targets.txt")
		o.FileOutput = o.FileInput

		require.ErrorIs(t, o.ValidateOptions(), input.ErrOutputIsInput)
	})

	t.Run("bypass file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.BypassFile = tempFile(t, "data.tsv")
		o.FileOutput = o.BypassFile

		require.ErrorIs(t, o.ValidateOptions(), input.ErrOutputIsInput)
	})

	t.Run("list file spelled differently is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileInput = tempFile(t, "targets.txt")
		o.FileOutput = filepath.Dir(o.FileInput) + "/./targets.txt"

		require.ErrorIs(t, o.ValidateOptions(), input.ErrOutputIsInput)
	})

	t.Run("link to the list file is rejected", func(t *testing.T) {
		t.Parallel()

		o := baseValidOptions()
		o.FileInput = tempFile(t, "targets.txt")
		o.FileOutput = filepath.Join(t.TempDir(), "link.txt")

		if err := os.Symlink(o.FileInput, o.FileOutput); err != nil {
			t.Skipf("cannot create a symlink: %s", err)
		}

		require.ErrorIs(t, o.ValidateOptions(), input.ErrOutputIsInput)
	})

	t.Run("device file is accepted, even as an input too", func(t *testing.T) {
		t.Parallel()

		if _, err := os.Stat(os.DevNull); err != nil || runtime.GOOS == "windows" {
			t.Skip("no null device")
		}

		// Opening a device does not empty it, as with -l /dev/stdin -o /dev/stdout.
		o := baseValidOptions()
		o.FileInput = os.DevNull
		o.FileOutput = os.DevNull

		require.NoError(t, o.ValidateOptions())
	})
}

func TestCheckProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy string
		want  bool
	}{
		{"empty", "", false},
		{"valid http proxy", "http://127.0.0.1:8080", true},
		{"valid https proxy", "https://proxy.example:443", true},
		{"valid socks proxy", "socks5://127.0.0.1:9050", true},
		{"valid socks5h proxy", "socks5h://127.0.0.1:9050", true},
		{"no port", "http://proxy.example", true},
		{"credentials", "http://user:pass@127.0.0.1:8080", true},
		{"upper-case scheme", "HTTP://127.0.0.1:8080", true},
		{"trailing slash", "http://127.0.0.1:8080/", true},
		{"ipv6 host", "http://[::1]:8080", true},
		{"malformed escape", "http://%zz", false},
		{"no scheme", "localhost:8080", false},
		{"no scheme, ip", "127.0.0.1:8080", false},
		{"bare host", "proxy.example", false},
		{"unsupported scheme", "ftp://proxy.example:21", false},
		{"socks4 is unsupported", "socks4://127.0.0.1:9050", false},
		{"no host", "http://", false},
		{"port only", "http://:8080", false},
		{"path only", "http:///proxy", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, input.CheckProxy(tt.proxy))
		})
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	t.Parallel()

	// Guard against accidental sentinel aliasing.
	require.False(t, errors.Is(input.ErrNoInput, input.ErrNegativeValue))
	require.False(t, errors.Is(input.ErrIsDirectory, fs.ErrNotExist))
	require.False(t, errors.Is(input.ErrOutputIsInput, input.ErrIsDirectory))
	require.False(t, errors.Is(input.ErrBadProxy, input.ErrMalformedURL))
}
