package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// scanSchedulerCap bounds the number of ScanService.Run goroutines that
// can be in flight simultaneously. Pre-Phase 3 the gate spawned one per
// upload with no bound; an image-scan workload (10× more CVE hydrate
// calls per run) could trivially overload the gate. The semaphore caps
// this; the test pins the cap behaviour.
func TestScanScheduler_CapsConcurrentRuns(t *testing.T) {
	sc := newScanScheduler(2)
	var inFlight, peak int64
	var mu sync.Mutex
	hold := make(chan struct{})
	var wg sync.WaitGroup

	work := func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sc.Acquire(ctx); err != nil {
			t.Errorf("Acquire: %v", err)
			return
		}
		defer sc.Release()
		v := atomic.AddInt64(&inFlight, 1)
		mu.Lock()
		if v > peak {
			peak = v
		}
		mu.Unlock()
		<-hold
		atomic.AddInt64(&inFlight, -1)
	}

	// Launch 5 workers; cap is 2. Only 2 should be in flight at any time.
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go work()
	}
	// Give the first cap-many workers time to start and pin their peak,
	// then assert no erroneous extra concurrency raced in.
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	got := peak
	mu.Unlock()
	if got != 2 {
		t.Errorf("peak concurrent runs = %d, want 2", got)
	}
	close(hold)
	wg.Wait()
}

// InFlight() must reflect the count of currently-acquired slots for
// monitoring (Prometheus gauge wires off it).
func TestScanScheduler_InFlight_TracksAcquireRelease(t *testing.T) {
	sc := newScanScheduler(4)
	if got := sc.InFlight(); got != 0 {
		t.Errorf("initial InFlight = %d, want 0", got)
	}
	ctx := context.Background()
	if err := sc.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sc.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sc.InFlight(); got != 2 {
		t.Errorf("after 2 Acquires, InFlight = %d, want 2", got)
	}
	sc.Release()
	if got := sc.InFlight(); got != 1 {
		t.Errorf("after 1 Release, InFlight = %d, want 1", got)
	}
	sc.Release()
	if got := sc.InFlight(); got != 0 {
		t.Errorf("after 2 Releases, InFlight = %d, want 0", got)
	}
}
