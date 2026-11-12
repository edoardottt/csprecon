/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package main

import (
	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/projectdiscovery/gologger"
)

func main() {
	options := input.ParseOptions()
	runner := csprecon.New(options)

	if err := runner.Run(); err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
}
