//go:build linux

package nfqueue

import (
	"testing"

	"github.com/getlantern/geneva/strategy"
)

type recorder struct {
	dirs []strategy.Direction
}

func (r *recorder) Observe(_ []byte, dir strategy.Direction) {
	r.dirs = append(r.dirs, dir)
}

func TestObserversFanOut(t *testing.T) {
	a, b := &recorder{}, &recorder{}
	obs := Observers(a, nil, b)
	obs.Observe([]byte{1}, strategy.DirectionInbound)
	if len(a.dirs) != 1 || len(b.dirs) != 1 {
		t.Fatalf("fan-out missed an observer: a=%v b=%v", a.dirs, b.dirs)
	}
}

func TestObserversNilWhenEmpty(t *testing.T) {
	// The runtime skips the observer call entirely on nil, so "no observers"
	// must not become a non-nil empty MultiObserver in the packet path.
	if got := Observers(); got != nil {
		t.Fatalf("Observers() = %v, want nil", got)
	}
	if got := Observers(nil, nil); got != nil {
		t.Fatalf("Observers(nil, nil) = %v, want nil", got)
	}
}

func TestObserversUnwrapsSingle(t *testing.T) {
	a := &recorder{}
	if got := Observers(nil, a); got != Observer(a) {
		t.Fatalf("Observers did not unwrap a single observer: %T", got)
	}
}
