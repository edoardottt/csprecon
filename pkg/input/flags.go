package input

import (
	"flag"
	"io"
	"os"
	"strings"

	"github.com/edoardottt/csprecon/pkg/output"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const (
	DefaultTimeout     = 10
	DefaultConcurrency = 100
)

type Options struct {
	Input       string
	FileInput   string
	FileOutput  string
	Domain      string
	Verbose     bool
	Output      io.Writer
	Silent      bool
	Concurrency int
	Timeout     int
}

// configureOutput configures the output on the screen.
func (options *Options) configureOutput() {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
}

// ParseOptions parses the command line options for application.
func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.Input, "u", "", `Input domain`)
	flag.StringVar(&options.FileInput, "l", "", `File containing input domains`)
	flag.StringVar(&options.Domain, "d", "", `Filter results belonging to this domain`)
	flag.StringVar(&options.FileOutput, "o", "", `File to write output results`)
	flag.BoolVar(&options.Verbose, "v", false, `Verbose output`)
	flag.BoolVar(&options.Silent, "s", false, `Print only results`)
	flag.IntVar(&options.Concurrency, "c", DefaultConcurrency, "Concurrency level")
	flag.IntVar(&options.Timeout, "t", DefaultTimeout, "Connection timeout in seconds")

	if help() {
		output.ShowBanner()
	}

	flag.Parse()

	// Read the inputs and configure the logging.
	options.configureOutput()

	if !options.Silent {
		output.ShowBanner()
	}

	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	return options
}

func help() bool {
	// help usage asked by user.
	for _, arg := range os.Args {
		argStripped := strings.Trim(arg, "-")
		if argStripped == "h" || argStripped == "help" {
			return true
		}
	}

	return false
}
