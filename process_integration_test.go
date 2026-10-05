//go:build integration

package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
	"golang.org/x/net/websocket"
)

func TestProcessStreams(t *testing.T) {
	old := httptest.NewServer(streamBackend("old"))
	defer old.Close()
	next := httptest.NewServer(streamBackend("new"))
	defer next.Close()
	cfg, store, cookie, _ := routerFixture(t, old.URL)
	store.Stop()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg.Server.Listen = addr
	cfg.Server.Hostnames = []string{"127.0.0.1"}
	cfg.Server.PublicOrigin = "http://" + addr
	cfg.Server.RPID = "127.0.0.1"
	if e = cfg.Save(); e != nil {
		t.Fatal(e)
	}
	binaryPath := os.Getenv("BOUNCER_TEST_BINARY")
	if binaryPath == "" {
		binaryPath = "bouncer"
	}
	binary, e := filepath.Abs(binaryPath)
	if e != nil {
		t.Fatal(e)
	}
	log, e := os.CreateTemp(t.TempDir(), "server-*.log")
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.Command(binary, "--config", cfg.Path())
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server exit: %v", err)
			}
		case <-time.After(7 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("server did not shut down within deadline")
		}
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, auth bool) (*http.Response, error) {
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		if auth {
			req.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: cookie})
		}
		return client.Do(req)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := request("/", false)
		if err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, path := range []string{"/events", "/ws"} {
		r, err := request(path, false)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 302 {
			t.Fatalf("unauthenticated %s: %d", path, r.StatusCode)
		}
	}
	// No client total timeout for an intentionally long-lived stream.
	streamClient := &http.Client{}
	req, _ := http.NewRequest("GET", "http://"+addr+"/events", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: cookie})
	resp, e := streamClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	events := make(chan string, 8)
	go func() {
		defer close(events)
		s := bufio.NewScanner(resp.Body)
		for s.Scan() {
			if strings.HasPrefix(s.Text(), "data:") {
				select {
				case events <- s.Text():
				default:
				}
			}
		}
	}()
	readEvent := func() {
		t.Helper()
		select {
		case text := <-events:
			if text != "data: old" {
				t.Fatalf("SSE %q", text)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("SSE buffered/stalled")
		}
	}
	readEvent()
	wsCfg, e := websocket.NewConfig("ws://"+addr+"/ws", cfg.Server.PublicOrigin)
	if e != nil {
		t.Fatal(e)
	}
	wsCfg.Header.Set("Cookie", cfg.Session.CookieName+"="+cookie)
	ws, e := websocket.DialConfig(wsCfg)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.Close()
	echo := func(text string) {
		t.Helper()
		_ = ws.SetDeadline(time.Now().Add(2 * time.Second))
		if e := websocket.Message.Send(ws, text); e != nil {
			t.Fatal(e)
		}
		var got string
		if e := websocket.Message.Receive(ws, &got); e != nil {
			t.Fatal(e)
		}
		if got != "old:"+text {
			t.Fatalf("WS %q", got)
		}
	}
	echo("before")
	disk, e := config.Load(cfg.Path())
	if e != nil {
		t.Fatal(e)
	}
	disk.Server.Backend = next.URL
	if e = disk.Save(); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Process.Signal(syscall.SIGHUP); e != nil {
		t.Fatal(e)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		r, err := request("/", true)
		if err == nil {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if strings.HasPrefix(string(body), "new|") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("reload did not select new backend")
		}
		time.Sleep(30 * time.Millisecond)
	}
	// Cross the server's 15s ReadTimeout and reload, without reconnecting.
	until := time.Now().Add(16 * time.Second)
	for time.Now().Before(until) {
		readEvent()
		echo("after")
		time.Sleep(200 * time.Millisecond)
	}
	disk, e = config.Load(cfg.Path())
	if e != nil {
		t.Fatal(e)
	}
	disk.Users = nil
	if e = disk.Save(); e != nil {
		t.Fatal(e)
	}
	_ = cmd.Process.Signal(syscall.SIGHUP)
	deadline = time.Now().Add(3 * time.Second)
	for {
		r, err := request("/events", true)
		if err == nil {
			r.Body.Close()
			if r.StatusCode == 302 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("removed user still authorized after reload")
		}
		time.Sleep(30 * time.Millisecond)
	}
	// Malformed reload fails closed without replacing the active generation.
	if e = os.WriteFile(cfg.Path(), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	_ = cmd.Process.Signal(syscall.SIGHUP)
	time.Sleep(100 * time.Millisecond)
	r, e := request("/events", true)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 302 {
		t.Fatal("failed reload changed auth state")
	}
}
