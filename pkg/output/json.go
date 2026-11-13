/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package output

import (
	"encoding/json"
)

// JSONData is the per-URL JSON output record.
type JSONData struct {
	URL string `json:"URL,omitempty"`
	// FinalURL is the page the CSP was read from, set only when URL redirected.
	FinalURL  string         `json:"FinalURL,omitempty"`
	CSPResult []string       `json:"CSPResult,omitempty"`
	Bypasses  []BypassResult `json:"Bypasses,omitempty"`
}

// BypassResult is a single known CSP bypass gadget matched against a target's
// enforced CSP.
type BypassResult struct {
	Domain    string   `json:"Domain,omitempty"`
	Directive string   `json:"Directive,omitempty"`
	Code      string   `json:"Code,omitempty"`
	Flags     []string `json:"Flags,omitempty"`
}

// FormatJSON returns the record marshalled as a JSON string.
func FormatJSON(data JSONData) ([]byte, error) {
	jsonOutput, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return jsonOutput, nil
}
