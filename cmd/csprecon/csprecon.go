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
