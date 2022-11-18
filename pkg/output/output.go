package output

import (
	"sync"
)

type Result struct {
	Map sync.Map
}

func New() Result {
	return Result{Map: sync.Map{}}
}

func (o *Result) Printed(result string) bool {
	if _, ok := o.Map.Load(result); !ok {
		o.Map.Store(result, true)
		return false
	}

	return true
}
