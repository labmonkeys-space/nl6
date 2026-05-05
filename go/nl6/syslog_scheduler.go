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

// Central syslog scheduler. A single goroutine owns a min-heap of
// (nextFire, deviceIP) entries. On each iteration it waits until the earliest
// due entry, consumes one token from the global rate limiter, and fires the
// device's SyslogExporter. Firing is a Poisson process per device: after each
// fire the device is requeued with an exponential-distributed next-fire offset
// (mean = -syslog-interval), naturally avoiding thundering-herd tick-boundary
// bursts (design.md §D1, §D2).
//
// This is intentionally the same shape as trap_scheduler.go — one min-heap
// goroutine keeps total timer count O(1) regardless of the 30k device fleet.
// Per design.md §D1 we copy rather than share: the trap and syslog subsystems
// carry independent rate caps and intervals, and a shared scheduler would
// require an abstract event interface that we'd rather defer until a third
// push-based capability appears.

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

// syslogFirer is the behaviour the scheduler needs from each registered
// device's SyslogExporter. Narrow interface to keep the scheduler decoupled
// from SyslogExporter internals and to let tests substitute mocks.
type syslogFirer interface {
	// Fire emits one message from the given catalog entry. Implementations
	// MUST be safe to call concurrently with Close; a fire on a closed
	// exporter SHOULD be a silent no-op so the scheduler can never deadlock
	// on a racing Deregister. The return value is the error from the encode
	// or UDP write if any — the scheduler logs and continues.
	Fire(entry *SyslogCatalogEntry, overrides map[string]string) error
}

// syslogHeapEntry is one queued device.
type syslogHeapEntry struct {
	nextFire time.Time
	deviceIP net.IP
	index    int
}

// syslogHeap implements heap.Interface. Earliest nextFire is popped first.
type syslogHeap []*syslogHeapEntry

func (h syslogHeap) Len() int           { return len(h) }
func (h syslogHeap) Less(i, j int) bool { return h[i].nextFire.Before(h[j].nextFire) }
func (h syslogHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *syslogHeap) Push(x interface{}) {
	e := x.(*syslogHeapEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *syslogHeap) Pop() interface{} {
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
// stored on DeviceSyslogConfig but not yet honored by the scheduler.
func (s *SyslogScheduler) MeanInterval() time.Duration { return s.meanInterval }

// SyslogScheduler coordinates per-device syslog firing with a single
// goroutine and a global token-bucket rate limiter. All fields are private;
// callers interact via Register / Deregister / Run / Stop.
type SyslogScheduler struct {
	mu      sync.Mutex
	heap    syslogHeap
	byIP    map[string]*syslogHeapEntry // lookup for Deregister
	devices map[string]syslogFirer      // exporter by device IP

	catalogFor   func(deviceIP net.IP) *SyslogCatalog
	meanInterval time.Duration
	limiter      *rate.Limiter // nil → no global cap

	// Injectable time/rand for deterministic tests. Production: now =
	// time.Now, rnd seeded from crypto/rand-derived time.
	now func() time.Time
	rnd *rand.Rand

	wake     chan struct{} // signalled by Register/Deregister/Stop to nudge Run
	stopCh   chan struct{}
	stopOnce sync.Once
}

// SyslogSchedulerOptions groups the tunables NewSyslogScheduler accepts. The
// zero value is not valid — a Catalog and a non-zero MeanInterval are
// required.
type SyslogSchedulerOptions struct {
	Catalog      *SyslogCatalog
	CatalogFor   func(deviceIP net.IP) *SyslogCatalog
	MeanInterval time.Duration
	// GlobalCapPerSecond is the maximum number of fires per second. Zero
	// means unlimited (the limiter is elided).
	GlobalCapPerSecond int
	// Seed, when non-zero, pins the RNG used for catalog picks and the
	// exponential inter-arrival draw. Primarily for tests.
	Seed int64
	// Now, when non-nil, overrides time.Now. Primarily for tests.
	Now func() time.Time
}

// NewSyslogScheduler constructs a scheduler but does not start it. Call Run
// to begin firing.
func NewSyslogScheduler(opts SyslogSchedulerOptions) *SyslogScheduler {
	if opts.Catalog == nil && opts.CatalogFor == nil {
		panic("NewSyslogScheduler: Catalog or CatalogFor required")
	}
	// Sub-millisecond intervals busy-loop the scheduler with no global cap.
	// 1ms is a generous floor — the 30k-device steady-state with cap=3k tps
	// (design.md §D2 default operating point) implies mean interval = 10s
	// per device, so a 1ms floor is well below any realistic production
	// setting and catches misconfiguration early.
	if opts.MeanInterval < time.Millisecond {
		panic("NewSyslogScheduler: MeanInterval must be >= 1ms")
	}
	catalogFor := opts.CatalogFor
	if catalogFor == nil {
		fixed := opts.Catalog
		catalogFor = func(net.IP) *SyslogCatalog { return fixed }
	}
	s := &SyslogScheduler{
		byIP:         make(map[string]*syslogHeapEntry),
		devices:      make(map[string]syslogFirer),
		catalogFor:   catalogFor,
		meanInterval: opts.MeanInterval,
		wake:         make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
	}
	if opts.GlobalCapPerSecond > 0 {
		// Burst = cap so short-term excursions fit within one second of
		// steady-state tokens. Matches trap_scheduler.go reasoning.
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
// preserved so re-registration doesn't double-fire.
func (s *SyslogScheduler) Register(deviceIP net.IP, firer syslogFirer) {
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
	// Initial fire: draw a Poisson offset from now. First-fire jitter
	// prevents every device firing immediately at startup.
	offset := time.Duration(s.rnd.ExpFloat64() * float64(s.meanInterval))
	entry := &syslogHeapEntry{
		nextFire: s.now().Add(offset),
		deviceIP: append(net.IP(nil), deviceIP...), // defensive copy
	}
	heap.Push(&s.heap, entry)
	s.byIP[key] = entry
	s.nudge()
}

// Deregister removes a device from the scheduler. Safe to call for devices
// that were never registered (no-op).
func (s *SyslogScheduler) Deregister(deviceIP net.IP) {
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

// Run blocks until ctx is cancelled or Stop is called. Loop: peek earliest,
// wait until its nextFire, Wait() for a limiter token, pop, requeue, fire
// outside the lock.
func (s *SyslogScheduler) Run(ctx context.Context) {
	// Derive a context that also cancels when Stop closes stopCh. Without
	// this, `limiter.Wait(ctx)` cannot observe Stop — callers would see
	// Run stay blocked for up to 1/rate seconds after Stop when a global
	// cap is configured.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("syslog scheduler: Run panicked: %v", r)
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
		entry := heap.Pop(&s.heap).(*syslogHeapEntry)
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

		// Snapshot IP and release before the manager callback to avoid
		// holding s.mu across sm.mu.RLock (same reasoning as trap
		// scheduler — decouples lock domains).
		deviceIP := entry.deviceIP
		s.mu.Unlock()

		cat := s.catalogFor(deviceIP)

		s.mu.Lock()
		var catEntry *SyslogCatalogEntry
		if cat != nil {
			catEntry = cat.Pick(s.rnd)
		}
		s.mu.Unlock()

		if catEntry != nil {
			s.fireWithRecover(firer, entry.deviceIP, catEntry)
		}
	}
}

// fireWithRecover wraps Fire with panic recovery so a misbehaving exporter
// can never take out the whole scheduler.
func (s *SyslogScheduler) fireWithRecover(firer syslogFirer, deviceIP net.IP, entry *SyslogCatalogEntry) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("syslog scheduler: Fire panicked for %s (entry=%s): %v",
				deviceIP, entry.Name, r)
		}
	}()
	if err := firer.Fire(entry, nil); err != nil {
		// Non-fatal: log and continue. Exporter-level stats track send
		// failures; the scheduler keeps firing for other devices.
		log.Printf("syslog scheduler: fire %s for %s: %v", entry.Name, deviceIP, err)
	}
}

// Stop signals Run to exit. Safe to call multiple times and from any goroutine.
func (s *SyslogScheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

// nudge signals the Run goroutine that the heap has changed. Non-blocking:
// a pending nudge collapses with this one.
func (s *SyslogScheduler) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
