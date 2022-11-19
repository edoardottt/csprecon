package output

import (
	"sync"
)

type Result struct {
	Map   map[string]struct{}
	Mutex *sync.RWMutex
}

func New() Result {
	return Result{
		Map:   map[string]struct{}{},
		Mutex: &sync.RWMutex{},
	}
}

func (o *Result) Printed(result string) bool {
	o.Mutex.RLock()
	if _, ok := o.Map[result]; !ok {
		o.Mutex.RUnlock()
		o.Mutex.Lock()
		o.Map[result] = struct{}{}
		o.Mutex.Unlock()

		return false
	} else {
		o.Mutex.RUnlock()
	}

	return true
}
