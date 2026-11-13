// Command foxker runs the Foxker backend: the dual SQLite graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"flag"
	"fmt"
	buildversion "github.com/Autumn-27/artex/version"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/selfupdate"
	"github.com/Autumn-27/artex/server"
)

// version is the build version. Default comes from the version package (the single
// source of truth) so a plain `go build ./cmd/foxker` reports the real repo version
// instead of "dev" — that "dev" default is what used to make the admin console show
// a stale/unknown version. Release builds still override it:
//
//	go build -ldflags "-X main.version=$(git describe --tags)" ./cmd/foxker
var version = buildversion.Version

const banner = `
    _    ____ _____ _______  __
   / \  |  _ \_   _| ____\ \/ /
  / _ \ | |_) || | |  _|  \  /
 / ___ \|  _ < | | | |___ /  \
/_/   \_\_| \_\|_| |_____/_/\_\
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  AI 自主渗透测试系统")
	fmt.Printf("  版本 %s  ·  %s/%s  ·  %s  ·  监听 %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// main only maps run's result onto the process exit code. The exit code is part
// of the update protocol — the supervising start script reads it to decide
// whether to relaunch us (see selfupdate.ExitRestart) — so the body has to live
// in a function that can *return* rather than os.Exit past its own defers.
func main() {
	os.Exit(run())
}

// warnIfPublic logs a reminder when -addr binds every interface, which is the
// default again: the console is reachable from the local network unless the
// operator passes "-addr 127.0.0.1:8787". It stays a log line rather than a hard
// block because that is exactly what the container image (the port mapping needs
// it), the release start scripts and LAN installs want — but it is worth one
// line at boot, since the /setup screen is all that is in front of the API.
func warnIfPublic(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// ":8787" splits cleanly; anything else is passed to the listener verbatim.
		host = addr
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return
	}
	log.Printf("[security] -addr %s 监听所有网卡，控制台对同网段可达（这是默认值）。仅本机访问请改用 "+
		"-addr 127.0.0.1:8787；容器/反代与确需远程访问时保持现状即可。", addr)
}

func run() int {
	var (
		// Default to every interface: the console has to be reachable from the
		// LAN/browser that is not the host itself (containers, LAN installs,
		// remote access), which is how the packaged start scripts and the image
		// run it. warnIfPublic prints one line at boot so the exposure is not
		// silent; an operator who wants host-only access passes
		// "-addr 127.0.0.1:8787".
		addr    = flag.String("addr", ":8787", "HTTP listen address (use \"127.0.0.1:8787\" for host-only access)")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory for SQLite stores (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "127.0.0.1:8788", "traffic recording proxy address (empty to disable)")
	)
	flag.Parse()

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// Self-update bootstrap: swap in a staged binary, or count a post-swap boot
	// attempt and roll back if the new build keeps dying. Must run before we open
	// the stores or bind a port — this may end with "exit and let the start script
	// relaunch me", and there is no point paying for either first.
	action, upState := selfupdate.Bootstrap()
	server.SetBootUpdateState(upState)
	if action == selfupdate.Restart {
		return selfupdate.ExitRestart
	}

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] 配置文件: %s", cfgPath)
	} else {
		log.Printf("[config] 配置文件: %s (不存在 — 将仅尝试环境变量 ARTEX_PG_DSN)", cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	// Surviving this long means a freshly swapped-in build actually works, so drop
	// the upgrade marker and stop counting attempts. Until it fires, every boot
	// increments the count and a build that keeps dying gets rolled back.
	settle := time.AfterFunc(selfupdate.SettleDelay, selfupdate.Settle)
	defer settle.Stop()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] skill 目录: %s", skillDir)
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Without an idle timeout a peer can hold connections open indefinitely
		// (one goroutine each) after finishing nothing but headers. IdleTimeout
		// covers keep-alive connections between requests; long requests, uploads
		// and SSE streams are unaffected because they are not idle.
		IdleTimeout: 120 * time.Second,
	}
	warnIfPublic(*addr)

	go func() {
		log.Printf("Foxker %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Two ways out: a signal (normal stop → exit 0, the start script stops looping)
	// or a staged update / rollback (→ exit 75, the script relaunches us and the
	// bootstrap above installs the new build).
	code := 0
	select {
	case <-ctx.Done():
	case <-server.RestartRequested():
		code = selfupdate.ExitRestart
		shutdown(agent.AbortShutdown)
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	// Stop the engines BEFORE the deferred mgr.Close() runs. The deferred order is
	// LIFO, so mgr.Close() (registered first) would otherwise close the PostgreSQL
	// pool while planner/worker loops are still writing: their final intent
	// state write-backs and activity inserts fail, leaving intents stuck in
	// 'running' across the restart. Stop cancels the server context and joins the
	// task runtimes within its own bound.
	srv.Stop()
	return code
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
