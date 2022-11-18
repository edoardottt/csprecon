package csprecon

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/golazy"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Runner struct {
	Client  *http.Client
	Input   chan string
	Output  chan string
	InWg    sync.WaitGroup
	OutWg   sync.WaitGroup
	Options input.Options
}

func New(options *input.Options) Runner {
	return Runner{
		Client:  customClient(options.Timeout),
		Input:   make(chan string),
		Output:  make(chan string),
		InWg:    sync.WaitGroup{},
		OutWg:   sync.WaitGroup{},
		Options: *options,
	}
}

func (r *Runner) Run() {
	r.InWg.Add(1)

	go pushInput(r)
	r.InWg.Add(1)

	go execute(r)
	r.OutWg.Add(1)

	go pullOutput(r)
	r.InWg.Wait()

	close(r.Output)
	r.OutWg.Wait()
}

func pushInput(r *Runner) {
	defer r.InWg.Done()

	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			r.Input <- scanner.Text()
		}
	}

	if r.Options.FileInput != "" {
		for _, line := range golazy.ReadFileLineByLine(r.Options.FileInput) {
			r.Input <- line
		}
	}

	if r.Options.Input != "" {
		r.Input <- r.Options.Input
	}

	close(r.Input)
}

func execute(r *Runner) {
	defer r.InWg.Done()
	for value := range r.Input {
		result, err := checkCSP(value, r.Client)
		if err == nil {
			for _, res := range result {
				r.Output <- res
			}
		}
	}
}

func pullOutput(r *Runner) {
	defer r.OutWg.Done()

	for o := range r.Output {
		r.OutWg.Add(1)
		go writeOutput(&r.OutWg, &r.Options, o)
	}
}

func writeOutput(wg *sync.WaitGroup, options *input.Options, out string) {
	defer wg.Done()
	if options.FileOutput != "" {
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		options.Output = file
	}

	// write output to file

	fmt.Println(out)
}
