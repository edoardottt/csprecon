/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package output

import (
	"encoding/json"
	"errors"
)

var ErrEmptyResult = errors.New("empty result")

// JSONResult.
type JSONResult struct {
	Result []JSONData `json:"Result,omitempty"`
}

// JSONData.
type JSONData struct {
	URL       string   `json:"URL,omitempty"`
	CSPResult []string `json:"CSPResult,omitempty"`
}

// FormatJSON returns the input as JSON string.
func FormatJSON(url string, result []string) ([]byte, error) {
	input := &JSONData{
		URL:       url,
		CSPResult: result,
	}

	jsonOutput, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	return jsonOutput, nil
}

func PrepareJSONOutput(out []string) (url string, result []string, err error) {
	if len(out) == 0 {
		return "", []string{}, ErrEmptyResult
	}

	if len(out) == 1 {
		return out[len(out)-1], []string{}, nil
	} else {
		return out[len(out)-1], out[0 : len(out)-2], nil
	}
}
