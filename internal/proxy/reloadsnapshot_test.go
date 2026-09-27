package proxy_test

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestReload_LogWritesNeverHitAClosedFile(t *testing.T) {
	dir := t.TempDir()
	openLog := func(i int) (*os.File, string) {
		path := filepath.Join(dir, fmt.Sprintf("%d.log", i))
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open log file: %v", err)
		}
		return f, path
	}

	targetURL, _ := url.Parse("https://example.com")
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	var logged syncBuffer
	srv.Logger = log.New(&logged, "", 0)
	first, firstPath := openLog(0)
	srv.LogFile = first
	paths := []string{firstPath}

	const writers, writesEach, reloads = 4, 500, 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				srv.LogEvent("tick", "x")
			}
		}()
	}
	var last *os.File
	for i := 1; i <= reloads; i++ {
		f, path := openLog(i)
		paths = append(paths, path)
		last = f
		srv.ReloadConfig(proxy.RuntimeConfig{Engine: rules.NewEngine(rules.Allow), LogFile: f, UpstreamTransport: proxy.NewUpstreamTransport(0)})
	}
	wg.Wait()
	defer last.Close()

	if strings.Contains(logged.String(), "write failed") {
		t.Errorf("a log write hit a closed file:\n%s", logged.String())
	}
	total := 0
	for _, path := range paths {
		total += len(logFileLines(t, path))
	}
	if total != writers*writesEach {
		t.Errorf("log lines across all files = %d, want %d", total, writers*writesEach)
	}
}
