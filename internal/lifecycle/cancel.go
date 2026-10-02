// Package lifecycle contains cancellation support compatible with Go 1.20.
package lifecycle

import (
	"context"
	"sync"
)

// OnCancel runs f when ctx ends. stop waits for the callback watcher to exit.
func OnCancel(ctx context.Context, f func()) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			f()
		case <-stop:
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-done }
}
