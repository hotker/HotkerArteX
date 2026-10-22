package agent

import (
	"context"
	"testing"
	"time"
)

// TestCompactorStopWaitsForBackgroundRun covers the lifecycle guarantee the server
// relies on: Stop must not return while a detached compaction is still running,
// because that goroutine writes into the exploration store.
func TestCompactorStopWaitsForBackgroundRun(t *testing.T) {
	c := NewCompactor(nil, "test")
	c.mu.Lock()
	c.running[1] = true
	c.mu.Unlock()

	c.wg.Add(1)
	release := make(chan struct{})
	go func() {
		defer c.wg.Done()
		<-release
	}()

	done := make(chan struct{})
	go func() {
		c.Stop(context.Background(), 5*time.Second)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Stop 在后台压缩结束前就返回了")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("后台压缩结束后 Stop 仍未返回")
	}
}

// TestCompactorStopIsBounded ensures a stuck compaction cannot hang shutdown: the
// timeout is honored and Stop still marks the compactor stopped.
func TestCompactorStopIsBounded(t *testing.T) {
	c := NewCompactor(nil, "test")
	c.wg.Add(1)
	defer c.wg.Done() // released only at test end

	start := time.Now()
	c.Stop(context.Background(), 50*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Stop 耗时 %v，未遵守超时", elapsed)
	}
	c.mu.Lock()
	stopped := c.stopped
	c.mu.Unlock()
	if !stopped {
		t.Fatal("Stop 后 stopped 仍为 false，新压缩会被启动")
	}
}

// TestCompactorTryStartAfterStop rejects new work once the compactor is stopped.
func TestCompactorTryStartAfterStop(t *testing.T) {
	c := NewCompactor(nil, "test")
	c.Stop(context.Background(), time.Second)
	if c.tryStart(1) {
		t.Fatal("Stop 之后仍能启动新的压缩")
	}
}

// TestCompactorStopNilIsSafe guards the nil-compactor path (feature disabled).
func TestCompactorStopNilIsSafe(t *testing.T) {
	var c *Compactor
	c.Stop(context.Background(), time.Second) // must not panic
	var p *Planner
	p.StopCompactor(context.Background(), time.Second)
}
