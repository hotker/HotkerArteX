"use client";

// visibleInterval is a drop-in replacement for setInterval in polling effects that
// stops firing while the tab is hidden.
//
// The UI polls a lot (task list, sessions, dashboard, logs badge — several timers
// at 2–5 s each). Every one of them keeps hitting the backend when the tab is
// backgrounded, which is exactly when nobody is looking: a laptop with five ARTEX
// tabs open kept the server busy and, on a metered connection, kept the radio
// awake. Browsers throttle background timers to ~1/minute but do not stop them,
// and a throttled poll still costs a request.
//
// Behaviour: the callback runs on the normal cadence while the page is visible.
// While hidden it is skipped entirely; on becoming visible again it fires once
// immediately (so the first thing the user sees is fresh, not stale), then the
// cadence resumes. Returns a cleanup function.
export function visibleInterval(fn: () => void | Promise<unknown>, ms: number): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  const hidden = () => typeof document !== "undefined" && document.hidden;

  // Pollers are async; setInterval used to discard the promise, which turned a
  // rejection into an unhandled-rejection warning. Swallow it here instead — the
  // next tick retries, and every poller already treats a failed poll as
  // "keep the previous data".
  const run = () => {
    try {
      const result = fn();
      if (result && typeof (result as Promise<unknown>).catch === "function") {
        void (result as Promise<unknown>).catch(() => {
          // Next tick retries; the poller keeps its previous data.
        });
      }
    } catch {
      // Synchronous failure: same rule, retry on the next tick.
    }
  };

  const schedule = () => {
    if (stopped) return;
    timer = setTimeout(tick, ms);
  };

  const tick = () => {
    if (stopped) return;
    if (!hidden()) run();
    schedule();
  };

  const onVisibility = () => {
    if (stopped || hidden()) return;
    // Come back to a live view: run now instead of waiting out the interval.
    if (timer) clearTimeout(timer);
    run();
    schedule();
  };

  if (typeof document !== "undefined") {
    document.addEventListener("visibilitychange", onVisibility);
  }
  schedule();

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    if (typeof document !== "undefined") {
      document.removeEventListener("visibilitychange", onVisibility);
    }
  };
}
