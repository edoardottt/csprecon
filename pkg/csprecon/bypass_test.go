/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"strings"
	"testing"

	"github.com/edoardottt/csprecon/pkg/csprecon"

	"github.com/stretchr/testify/require"
)

func TestParseBypassData(t *testing.T) {
	data := "Domain\tCode\n" +
		"ajax.googleapis.com\t<script src=\"https://ajax.googleapis.com/x\"></script>\n" +
		"\n" +
		"a.config.skype.com\t<script src=\"https://a.config.skype.com/y\"></script>\n"

	got := csprecon.ParseBypassData(strings.NewReader(data))

	require.Len(t, got, 2)
	require.Contains(t, got, "ajax.googleapis.com")
	require.Contains(t, got, "a.config.skype.com")
	require.NotContains(t, got, "Domain")
}

func TestLookupBypass(t *testing.T) {
	gadgets := map[string]string{
		"ajax.googleapis.com": "gadget-google",
		"a.config.skype.com":  "gadget-skype",
	}

	tests := []struct {
		name     string
		domain   string
		wantCode string
		wantOk   bool
	}{
		{"exact match", "ajax.googleapis.com", "gadget-google", true},
		{"wildcard match", "*.googleapis.com", "gadget-google", true},
		{"no match", "example.com", "", false},
		{"empty domain", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, ok := csprecon.LookupBypass(tt.domain, gadgets)
			require.Equal(t, tt.wantOk, ok)
			require.Equal(t, tt.wantCode, code)
		})
	}
}

func TestLookupBypassEmptyDB(t *testing.T) {
	code, ok := csprecon.LookupBypass("ajax.googleapis.com", map[string]string{})
	require.False(t, ok)
	require.Empty(t, code)
}
