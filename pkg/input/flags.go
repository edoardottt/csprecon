package input

import (
	"io"
	"os"
	"strings"

	"github.com/edoardottt/csprecon/pkg/output"
	"github.com/projectdiscovery/goflags"
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
	Domain      goflags.StringSlice
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

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Discover new target domains using Content Security Policy.`)

	// Input
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVar(&options.Input, "u", "", `Input domain`),
		flagSet.StringVar(&options.FileInput, "l", "", `File containing input domains`),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringSliceVar(&options.Domain, "d", nil, `Filter results belonging to these domains (comma separated)`, goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVar(&options.Concurrency, "c", DefaultConcurrency, `Concurrency level`),
		flagSet.IntVar(&options.Timeout, "t", DefaultTimeout, `Connection timeout in seconds`),
	)

	// Output
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVar(&options.FileOutput, "o", "", `File to write output results`),
		flagSet.BoolVar(&options.Verbose, "v", false, `Verbose output`),
		flagSet.BoolVar(&options.Silent, "s", false, `Print only results`),
	)

	if help() || noArgs() || !options.Silent {
		output.ShowBanner()
	}

	if err := flagSet.Parse(); err != nil {
		output.ShowBanner()
		gologger.Fatal().Msgf("%s\n", err)
	}

	// Read the inputs and configure the logging.
	options.configureOutput()

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

func noArgs() bool {
	// User passed no flag.
	return len(os.Args) < 2
}
