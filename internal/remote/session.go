package remote

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"fpp-agent-monitor/internal/log"
)

type Manager struct {
	Logger   *log.Logger
	TunnelToken    string
	TunnelHostname string
	mu       sync.Mutex
	cmd      *exec.Cmd
	cmdCancel context.CancelFunc
	session  string
	url      string
	binPath  string
	cleanBin bool
	proxyToken    string
	proxyTarget   *url.URL
	proxyServer   *http.Server
	proxyListener net.Listener
}

type OpenParams struct {
	SessionID      string
	TargetURL      string
	IdleTimeoutSec int
	SessionToken   string
}

type OpenResult struct {
	URL string `json:"url"`
}

func (m *Manager) Open(ctx context.Context, params OpenParams) (OpenResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil {
		return OpenResult{}, errors.New("session_active")
	}
	if strings.TrimSpace(m.TunnelToken) == "" {
		return OpenResult{}, errors.New("tunnel_token_missing")
	}
	if strings.TrimSpace(m.TunnelHostname) == "" {
		return OpenResult{}, errors.New("tunnel_hostname_missing")
	}
	if strings.TrimSpace(params.SessionToken) == "" {
		return OpenResult{}, errors.New("session_token_missing")
	}

	target := strings.TrimSpace(params.TargetURL)
	if target == "" {
		target = "http://127.0.0.1"
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		return OpenResult{}, errors.New("invalid_target_url")
	}

	path, clean, err := ensureCloudflared(ctx)
	if err != nil {
		return OpenResult{}, err
	}
	m.binPath = path
	m.cleanBin = clean
	if err := m.startProxy(targetURL, params.SessionToken); err != nil {
		return OpenResult{}, err
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(
		cmdCtx,
		path,
		"--no-autoupdate",
		"tunnel",
		"run",
		"--url",
		fmt.Sprintf("http://%s", m.proxyListener.Addr().String()),
		"--token",
		m.TunnelToken,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return OpenResult{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return OpenResult{}, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return OpenResult{}, err
	}
	m.cmd = cmd
	m.cmdCancel = cancel
	m.session = params.SessionID

	url := strings.TrimSpace(m.TunnelHostname)
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	m.url = url
	m.Logger.Info("session_opened", map[string]interface{}{"session_id": params.SessionID, "url": url})

	readStream := func(name string, r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			m.Logger.Info("cloudflared_log", map[string]interface{}{
				"session_id": params.SessionID,
				"stream":     name,
				"line":       line,
			})
		}
	}

	go readStream("stdout", stdout)
	go readStream("stderr", stderr)

	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cmd == cmd {
			if err != nil {
				m.Logger.Warn("cloudflared_exit", map[string]interface{}{
					"session_id": params.SessionID,
					"error":      err.Error(),
				})
			}
			m.Logger.Info("session_closed", map[string]interface{}{"session_id": params.SessionID})
			m.stopLocked()
		}
	}()

	return OpenResult{URL: url}, nil
}

func (m *Manager) Close(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd == nil {
		return nil
	}
	if sessionID != "" && m.session != sessionID {
		return errors.New("session_mismatch")
	}
	m.stopLocked()
	return nil
}

func (m *Manager) stopLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	m.cmd = nil
	if m.cmdCancel != nil {
		m.cmdCancel()
	}
	m.cmdCancel = nil
	m.session = ""
	m.url = ""
	if m.cleanBin && m.binPath != "" {
		_ = os.Remove(m.binPath)
	}
	m.binPath = ""
	m.cleanBin = false
	if m.proxyServer != nil {
		_ = m.proxyServer.Close()
	}
	if m.proxyListener != nil {
		_ = m.proxyListener.Close()
	}
	m.proxyServer = nil
	m.proxyListener = nil
	m.proxyToken = ""
	m.proxyTarget = nil
}

func (m *Manager) startProxy(targetURL *url.URL, token string) error {
	if m.proxyListener != nil {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	m.proxyListener = ln
	m.proxyToken = token
	m.proxyTarget = targetURL

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "upstream_unreachable", http.StatusBadGateway)
	}
	m.proxyServer = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			prefix := "/_showops/" + m.proxyToken + "/"
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = "/" + strings.TrimPrefix(r.URL.Path, prefix)
			r.Host = targetURL.Host
			proxy.ServeHTTP(w, r)
		}),
	}

	go func() {
		_ = m.proxyServer.Serve(ln)
	}()
	return nil
}

func waitForTunnelURL(stdout io.Reader, stderr io.Reader, timeout time.Duration) (string, error) {
	outCh := make(chan string, 1)
	errCh := make(chan error, 1)

	readStream := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "trycloudflare.com") {
				for _, token := range strings.Fields(line) {
					if strings.HasPrefix(token, "https://") && strings.Contains(token, "trycloudflare.com") {
						outCh <- token
						return
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
		}
	}

	go readStream(stdout)
	go readStream(stderr)

	select {
	case url := <-outCh:
		return url, nil
	case err := <-errCh:
		return "", err
	case <-time.After(timeout):
		return "", errors.New("tunnel_timeout")
	}
}

func ensureCloudflared(ctx context.Context) (string, bool, error) {
	if path, err := exec.LookPath("cloudflared"); err == nil {
		return path, false, nil
	}

	if runtime.GOOS != "linux" {
		return "", false, errors.New("cloudflared_not_available")
	}

	arch := map[string]string{
		"amd64": "amd64",
		"arm64": "arm64",
		"arm":   "arm",
	}[runtime.GOARCH]
	if arch == "" {
		return "", false, fmt.Errorf("cloudflared_unsupported_arch_%s", runtime.GOARCH)
	}

	url := fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-%s", arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("cloudflared_download_failed_%d", resp.StatusCode)
	}

	tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("cloudflared-%d", time.Now().UnixNano()))
	out, err := os.Create(tmpPath)
	if err != nil {
		return "", false, err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return "", false, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmpPath)
		return "", false, err
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return "", false, err
	}
	return tmpPath, true, nil
}

func EncodeResult(result OpenResult) string {
	b, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(b)
}
