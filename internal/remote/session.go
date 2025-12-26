package remote

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	session  string
	url      string
	binPath  string
	cleanBin bool
}

type OpenParams struct {
	SessionID      string
	TargetURL      string
	IdleTimeoutSec int
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

	target := strings.TrimSpace(params.TargetURL)
	if target == "" {
		target = "http://127.0.0.1"
	}

	path, clean, err := ensureCloudflared(ctx)
	if err != nil {
		return OpenResult{}, err
	}
	m.binPath = path
	m.cleanBin = clean

	cmd := exec.CommandContext(
		ctx,
		path,
		"tunnel",
		"--url",
		target,
		"--no-autoupdate",
		"--token",
		m.TunnelToken,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return OpenResult{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return OpenResult{}, err
	}

	if err := cmd.Start(); err != nil {
		return OpenResult{}, err
	}
	m.cmd = cmd
	m.session = params.SessionID

	url := strings.TrimSpace(m.TunnelHostname)
	if url == "" {
		parsed, err := waitForTunnelURL(stdout, stderr, 20*time.Second)
		if err != nil {
			m.stopLocked()
			return OpenResult{}, err
		}
		url = parsed
	}
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	m.url = url
	m.Logger.Info("session_opened", map[string]interface{}{"session_id": params.SessionID, "url": url})

	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cmd == cmd {
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
	m.session = ""
	m.url = ""
	if m.cleanBin && m.binPath != "" {
		_ = os.Remove(m.binPath)
	}
	m.binPath = ""
	m.cleanBin = false
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
