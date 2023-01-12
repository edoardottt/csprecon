/*
csprecon - Discover new target domains using Content Security Policy

This repository is under MIT License https://github.com/edoardottt/csprecon/blob/main/LICENSE
*/

package main

import (
	"github.com/edoardottt/csprecon/pkg/csprecon"
	"github.com/edoardottt/csprecon/pkg/input"
)

func main() {
	options := input.ParseOptions()
	runner := csprecon.New(options)
	runner.Run()
}
