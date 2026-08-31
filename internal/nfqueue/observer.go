//go:build linux

package nfqueue

import "github.com/getlantern/geneva/strategy"

// MultiObserver fans one packet out to several observers in order. It exists
// because the runtime has two independent watchers with different lifetimes:
// the eval-mode canary pool, which only runs on test boxes, and the inbound
// censor classifier, which runs in both modes.
type MultiObserver []Observer

// Observe forwards raw to every observer. Observers must not retain the slice,
// which is the same contract a single Observer already has.
func (m MultiObserver) Observe(raw []byte, dir strategy.Direction) {
	for _, o := range m {
		o.Observe(raw, dir)
	}
}

// Observers builds an Observer from the non-nil members of obs. It returns nil
// when none are present, so the runtime's per-packet nil check keeps the
// observer path out of the hot loop entirely, and returns the single member
// unwrapped when there is exactly one.
func Observers(obs ...Observer) Observer {
	present := make(MultiObserver, 0, len(obs))
	for _, o := range obs {
		if o != nil {
			present = append(present, o)
		}
	}
	switch len(present) {
	case 0:
		return nil
	case 1:
		return present[0]
	default:
		return present
	}
}
