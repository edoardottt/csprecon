package csprecon

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/edoardottt/csprecon/pkg/input"
	"github.com/edoardottt/golazy"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Runner struct {
	Input   chan string
	Output  chan string
	InWg    sync.WaitGroup
	OutWg   sync.WaitGroup
	Options input.Options
}

func New(options *input.Options) Runner {
	return Runner{
		Input:   make(chan string),
		Output:  make(chan string),
		InWg:    sync.WaitGroup{},
		OutWg:   sync.WaitGroup{},
		Options: *options,
	}
}

func (r *Runner) Run() {
	r.InWg.Add(1)
	go pushInput(&r.InWg, &r.Options, r.Input)

	r.InWg.Add(1)
	go execute(&r.InWg, &r.Options, r.Input, r.Output)

	r.OutWg.Add(1)
	go pullOutput(&r.OutWg, &r.Options, r.Output)

	r.InWg.Wait()

	close(r.Output)
	r.OutWg.Wait()
}

func pushInput(wg *sync.WaitGroup, options *input.Options, inputchan chan string) {
	defer wg.Done()

	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			inputchan <- scanner.Text()
		}
	}

	if options.FileInput != "" {
		for _, line := range golazy.ReadFileLineByLine(options.FileInput) {
			inputchan <- line
		}
	}

	if options.Input != "" {
		inputchan <- options.Input
	}

	close(inputchan)
}

func execute(wg *sync.WaitGroup, options *input.Options, inputchan chan string, outputchan chan string) {
	defer wg.Done()
	for value := range inputchan {
		result, err := checkCSP(value)
		if err == nil {
			fmt.Println(result)
			outputchan <- *result
		}
	}
}

func pullOutput(wg *sync.WaitGroup, options *input.Options, outputchan chan string) {
	defer wg.Done()

	for o := range outputchan {
		wg.Add(1)
		go writeOutput(wg, options, o)
	}
}

func writeOutput(wg *sync.WaitGroup, options *input.Options, out url.URL) {
	defer wg.Done()
	if options.FileOutput != "" {
		file, err := os.OpenFile(options.FileOutput, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		options.Output = file
	}

	//write output to file
}
