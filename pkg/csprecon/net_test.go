/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package csprecon_test

import (
	"testing"

	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"

	"github.com/stretchr/testify/require"
)

func TestPrepareURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		err   error
	}{
		{
			name:  "empty",
			input: "",
			want:  "",
			err:   input.ErrMalformedURL,
		},
		{
			name:  "minUrlLength",
			input: "a.b",
			want:  "",
			err:   input.ErrMalformedURL,
		},
		{
			name:  "ok1",
			input: "a.co",
			want:  "http://a.co",
			err:   nil,
		},
		{
			name:  "ok1withProtocol",
			input: "http://a.co",
			want:  "http://a.co",
			err:   nil,
		},
		{
			name:  "ok1",
			input: "a.b.c.d.e.co",
			want:  "http://a.b.c.d.e.co",
			err:   nil,
		},
		{
			name:  "ok1withProtocol",
			input: "http://a.b.c.d.e.co",
			want:  "http://a.b.c.d.e.co",
			err:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := csprecon.PrepareURL(tt.input)
			require.Equal(t, tt.err, err)
			require.Equal(t, tt.want, got)
		})
	}
}
