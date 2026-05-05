/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Central trap scheduler. A single goroutine owns a min-heap of
// (nextFire, deviceIP) entries. On each iteration it waits until the earliest
// due entry, consumes one token from the global rate limiter, and fires the
// device's TrapExporter. Firing is a Poisson process per device: after each
// fire the device is requeued with an exponential-distributed next-fire offset
// (mean = -trap-interval), which naturally avoids thundering-herd tick-boundary
// bursts (design.md §D1, §D2).
//
// Scale note: a `time.Ticker` per device would mean 30,000 goroutines and
// 30,000 timers in the runtime's timer heap. A single scheduler goroutine with
// an explicit min-heap keeps both counts at O(1) regardless of device count.

package main

import (
	"container/heap"
	"context"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// trapFirer is the behaviour the scheduler needs from each registered device's
// TrapExporter. Keeping it as a narrow interface decouples the scheduler from
// TrapExporter internals (and lets tests substitute mocks).
type trapFirer interface {
	// Fire emits one trap from the given catalog entry. Implementations MUST
	// be safe to call concurrently with Close; a fire on a closed exporter
	// SHOULD be a silent no-op so the scheduler can never deadlock on a
	// racing Deregister. The returned request-id is used by the HTTP API
	// handler; the scheduler ignores it.
	Fire(entry *CatalogEntry, overrides map[string]string) uint32
}

// trapHeapEntry is one queued device. nextFire is the absolute wall-clock
// time the device is next due to fire. The index field is maintained by
// container/heap so heap.Fix / heap.Remove can locate entries by pointer.
type trapHeapEntry struct {
	nextFire time.Time
	deviceIP net.IP
	index    int
}

// trapHeap implements heap.Interface for a slice of *trapHeapEntry. Earliest
// nextFire is popped first.
type trapHeap []*trapHeapEntry

func (h trapHeap) Len() int           { return len(h) }
func (h trapHeap) Less(i, j int) bool { return h[i].nextFire.Before(h[j].nextFire) }
func (h trapHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *trapHeap) Push(x interface{}) {
	e := x.(*trapHeapEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *trapHeap) Pop() interface{} {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// MeanInterval returns the simulator-wide mean firing interval. Exposed
// for per-device-attach divergence warnings — per-device intervals are
// stored on DeviceTrapConfig but not yet honored by the scheduler.
func (s *TrapScheduler) MeanInterval() time.Duration { return s.meanInterval }

// TrapScheduler coordinates per-device trap firing with a single goroutine
// and a global token-bucket rate limiter. All fields are private; callers
// interact via Register / Deregister / Run / Stop.
//
// The scheduler does not own the catalog directly — it resolves a catalog
// per-fire via `catalogFor(deviceIP)`, which the manager implements over
// `trapCatalogsByType`. This keeps per-type catalog lifecycle on the
// manager, where `_universal` resolution and future per-type metrics live.
type TrapScheduler struct {
	mu      sync.Mutex
	heap    trapHeap
	byIP    map[string]*trapHeapEntry // lookup for Deregister
	devices map[string]trapFirer      // exporter by device IP

	catalogFor   func(deviceIP net.IP) *Catalog
	meanInterval time.Duration
	limiter      *rate.Limiter // nil → no global cap

	// Injectable time/rand for deterministic tests. In production, now =
	// time.Now and rnd is seeded from crypto/rand in NewTrapScheduler.
	now func() time.Time
	rnd *rand.Rand

	wake     chan struct{} // signalled by Register/Deregister/Stop to nudge Run
	stopCh   chan struct{}
	stopOnce sync.Once
}

// SchedulerOptions groups the tunables that NewTrapScheduler accepts. The
// zero value is not valid — either Catalog or CatalogFor must be set, and
// MeanInterval must be positive.
//
// CatalogFor (preferred) enables per-device-type catalog resolution. When
// set, the scheduler calls it per fire to look up the device's effective
// catalog. Catalog (legacy) is a single catalog shared by every device —
// when CatalogFor is nil the scheduler wraps Catalog in a constant
// callback so existing call sites and tests continue to work.
type SchedulerOptions struct {
	Catalog      *Catalog
	CatalogFor   func(deviceIP net.IP) *Catalog
	MeanInterval time.Duration
	// GlobalCapPerSecond is the maximum number of fires+retries per second.
	// Zero means unlimited (the limiter is elided).
	GlobalCapPerSecond int
	// Seed, when non-zero, pins the RNG used for catalog picks and the
	// exponential inter-arrival draw. Primarily for tests.
	Seed int64
	// Now, when non-nil, overrides time.Now. Primarily for tests.
	Now func() time.Time
}

// NewTrapScheduler constructs a scheduler but does not start it. Call Run to
// begin firing.
func NewTrapScheduler(opts SchedulerOptions) *TrapScheduler {
	if opts.Catalog == nil && opts.CatalogFor == nil {
		panic("NewTrapScheduler: Catalog or CatalogFor required")
	}
	if opts.MeanInterval <= 0 {
		panic("NewTrapScheduler: MeanInterval must be positive")
	}
	catalogFor := opts.CatalogFor
	if catalogFor == nil {
		// Legacy single-catalog mode: wrap the static catalog in a
		// constant callback so the fire loop is shape-stable regardless
		// of whether per-type resolution is in use.
		fixed := opts.Catalog
		catalogFor = func(net.IP) *Catalog { return fixed }
	}
	s := &TrapScheduler{
		byIP:         make(map[string]*trapHeapEntry),
		devices:      make(map[string]trapFirer),
		catalogFor:   catalogFor,
		meanInterval: opts.MeanInterval,
		wake:         make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
	}
	if opts.GlobalCapPerSecond > 0 {
		// Burst = cap so short-term excursions fit within one second of
		// steady-state tokens. Larger bursts let one device's retry storm
		// eat the whole budget. One-second burst is the tightest sane value.
		s.limiter = rate.NewLimiter(rate.Limit(opts.GlobalCapPerSecond), opts.GlobalCapPerSecond)
	}
	if opts.Now != nil {
		s.now = opts.Now
	} else {
		s.now = time.Now
	}
	seed := opts.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	s.rnd = rand.New(rand.NewSource(seed))
	return s
}

// Register wires a device into the scheduler. If the device is already
// registered (same IP), its exporter is replaced but the next-fire time is
// preserved, so re-registration doesn't double-fire.
func (s *TrapScheduler) Register(deviceIP net.IP, firer trapFirer) {
	if firer == nil {
		return
	}
	key := deviceIP.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[key] = firer
	if _, already := s.byIP[key]; already {
		return
	}
	// Initial fire: draw a Poisson offset from now. First-fire jitter prevents
	// every device firing immediately at startup.
	offset := time.Duration(s.rnd.ExpFloat64() * float64(s.meanInterval))
	entry := &trapHeapEntry{
		nextFire: s.now().Add(offset),
		deviceIP: append(net.IP(nil), deviceIP...), // defensive copy
	}
	heap.Push(&s.heap, entry)
	s.byIP[key] = entry
	s.nudge()
}

// Deregister removes a device from the scheduler. Safe to call for devices
// that were never registered (no-op).
func (s *TrapScheduler) Deregister(deviceIP net.IP) {
	key := deviceIP.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.byIP[key]
	if !ok {
		delete(s.devices, key)
		return
	}
	if entry.index >= 0 && entry.index < s.heap.Len() {
		heap.Remove(&s.heap, entry.index)
	}
	delete(s.byIP, key)
	delete(s.devices, key)
	s.nudge()
}

// Run blocks until ctx is cancelled or Stop is called. The loop: peek
// earliest, wait until its nextFire, Wait() for a limiter token, pop, requeue,
// fire outside the lock.
func (s *TrapScheduler) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("trap scheduler: Run panicked: %v", r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		s.mu.Lock()
		if s.heap.Len() == 0 {
			s.mu.Unlock()
			// Wait until someone registers or we're stopped.
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-s.wake:
				continue
			}
		}
		nextFire := s.heap[0].nextFire
		s.mu.Unlock()

		delay := nextFire.Sub(s.now())
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-s.stopCh:
				timer.Stop()
				return
			case <-s.wake:
				// Heap changed while waiting (Register/Deregister). Re-peek.
				timer.Stop()
				continue
			case <-timer.C:
			}
		}

		if s.limiter != nil {
			if err := s.limiter.Wait(ctx); err != nil {
				return
			}
		}

		s.mu.Lock()
		if s.heap.Len() == 0 {
			s.mu.Unlock()
			continue
		}
		entry := heap.Pop(&s.heap).(*trapHeapEntry)
		key := entry.deviceIP.String()
		firer, firerExists := s.devices[key]

		if !firerExists {
			// Deregistered while we waited; drop the entry.
			delete(s.byIP, key)
			s.mu.Unlock()
			continue
		}

		// Requeue with an exponential-distributed offset.
		offset := time.Duration(s.rnd.ExpFloat64() * float64(s.meanInterval))
		entry.nextFire = s.now().Add(offset)
		heap.Push(&s.heap, entry)
		s.byIP[key] = entry

		// Snapshot IP under the lock so we can release before calling
		// the manager callback (which takes sm.mu.RLock). Holding s.mu
		// across the callback creates an A→B/B→A lock-order hazard with
		// any code path that later takes sm.mu.Lock and then touches the
		// scheduler; decoupling removes the invariant's fragility.
		deviceIP := entry.deviceIP
		s.mu.Unlock()

		cat := s.catalogFor(deviceIP)

		// Pick requires the lock because rnd is not concurrent-safe.
		s.mu.Lock()
		var trapEntry *CatalogEntry
		if cat != nil {
			trapEntry = cat.Pick(s.rnd)
		}
		s.mu.Unlock()

		if trapEntry != nil {
			s.fireWithRecover(firer, entry.deviceIP, trapEntry)
		}
	}
}

// fireWithRecover wraps Fire with panic recovery so a misbehaving exporter
// can never take out the whole scheduler.
func (s *TrapScheduler) fireWithRecover(firer trapFirer, deviceIP net.IP, entry *CatalogEntry) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("trap scheduler: Fire panicked for %s (trap=%s): %v",
				deviceIP, entry.Name, r)
		}
	}()
	firer.Fire(entry, nil)
}

// Stop signals Run to exit. Safe to call multiple times and from any goroutine.
func (s *TrapScheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

// nudge signals the Run goroutine that the heap has changed. Non-blocking:
// if a previous nudge is pending, this one collapses into it.
func (s *TrapScheduler) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
