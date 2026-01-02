package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"fpp-agent-monitor/internal/config"
	"fpp-agent-monitor/internal/log"
	"fpp-agent-monitor/internal/remote"
	"fpp-agent-monitor/internal/update"
)

type Executor struct {
	Logger            *log.Logger
	UpdateEnabled     bool
	AllowDowngrade    bool
	UpdateChannel     string
	DownloadsDir      string
	BinaryPath        string
	ConfigPath        string
	RebootEnabled     bool
	RestartFPPCommand string
	FPPBaseURL        string
	AllowCIDRs        []string
	AllowPorts        []int
	CommandTimeout    time.Duration
	SessionManager    *remote.Manager
}

type Result struct {
	Status     string
	Output     string
	Error      string
	ShouldExit bool
}

func (e *Executor) Execute(ctx context.Context, cmdType string, payload map[string]interface{}) Result {
	ctx, cancel := context.WithTimeout(ctx, e.CommandTimeout)
	defer cancel()

	switch cmdType {
	case "restart_agent":
		return Result{Status: "success", Output: "exiting for restart", ShouldExit: true}
	case "update_agent":
		return e.updateAgent(ctx, payload)
	case "reboot_host":
		return e.rebootHost(ctx)
	case "restart_fpp":
		return e.restartFPP(ctx)
	case "network_probe":
		return e.networkProbe(ctx, payload)
	case "session_open":
		return e.openSession(ctx, payload)
	case "session_close":
		return e.closeSession(ctx, payload)
	case "tunnel_config":
		return e.updateTunnelConfig(ctx, payload)
	case "plugin_update":
		return e.pluginUpdate(ctx, payload)
	case "playlist_start":
		return e.startPlaylist(ctx, payload)
	case "playlist_stop":
		return e.stopPlaylist(ctx, payload)
	default:
		return Result{Status: "error", Error: "command_not_allowed"}
	}
}

func (e *Executor) updateAgent(ctx context.Context, payload map[string]interface{}) Result {
	if !e.UpdateEnabled {
		return Result{Status: "error", Error: "updates_disabled"}
	}
	url, _ := payload["url"].(string)
	sha, _ := payload["sha256"].(string)
	if url == "" || sha == "" {
		return Result{Status: "error", Error: "missing_update_fields"}
	}

	err := update.Apply(ctx, e.Logger, update.Params{
		URL:          url,
		SHA256:       sha,
		DownloadDir:  e.DownloadsDir,
		BinaryPath:   e.BinaryPath,
		AllowFileExt: true,
	})
	if err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	return Result{Status: "success", Output: "updated", ShouldExit: true}
}

func (e *Executor) rebootHost(ctx context.Context) Result {
	if !e.RebootEnabled {
		return Result{Status: "error", Error: "reboot_disabled"}
	}
	cmd := exec.CommandContext(ctx, "/sbin/reboot")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Result{Status: "error", Error: err.Error(), Output: string(out)}
	}
	return Result{Status: "success", Output: string(out)}
}

func (e *Executor) restartFPP(ctx context.Context) Result {
	if strings.TrimSpace(e.RestartFPPCommand) == "" {
		return Result{Status: "error", Error: "restart_fpp_not_configured"}
	}
	parts := strings.Fields(e.RestartFPPCommand)
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Result{Status: "error", Error: err.Error(), Output: string(out)}
	}
	return Result{Status: "success", Output: string(out)}
}

func (e *Executor) networkProbe(ctx context.Context, payload map[string]interface{}) Result {
	host, _ := payload["host"].(string)
	mode, _ := payload["mode"].(string)
	portFloat, _ := payload["port"].(float64)
	port := int(portFloat)
	if host == "" || port == 0 {
		return Result{Status: "error", Error: "missing_host_or_port"}
	}
	if !e.allowedTarget(host, port) {
		return Result{Status: "error", Error: "target_not_allowlisted"}
	}

	timeout := time.Duration(1500) * time.Millisecond
	if t, ok := payload["timeout_ms"].(float64); ok && t > 0 {
		timeout = time.Duration(int64(t)) * time.Millisecond
	}

	switch mode {
	case "ping":
		return e.pingHost(ctx, host, timeout)
	case "tcp", "":
		return e.tcpProbe(ctx, host, port, timeout)
	default:
		return Result{Status: "error", Error: "unsupported_probe_mode"}
	}
}

func (e *Executor) openSession(ctx context.Context, payload map[string]interface{}) Result {
	if e.SessionManager == nil {
		return Result{Status: "error", Error: "session_manager_missing"}
	}
	sessionID, _ := payload["session_id"].(string)
	targetURL, _ := payload["target_url"].(string)
	idleFloat, _ := payload["idle_timeout_sec"].(float64)
	sessionToken, _ := payload["session_token"].(string)
	idleTimeout := int(idleFloat)
	result, err := e.SessionManager.Open(ctx, remote.OpenParams{
		SessionID:      sessionID,
		TargetURL:      targetURL,
		IdleTimeoutSec: idleTimeout,
		SessionToken:   sessionToken,
	})
	if err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	return Result{Status: "success", Output: remote.EncodeResult(result)}
}

func (e *Executor) closeSession(ctx context.Context, payload map[string]interface{}) Result {
	if e.SessionManager == nil {
		return Result{Status: "error", Error: "session_manager_missing"}
	}
	sessionID, _ := payload["session_id"].(string)
	if err := e.SessionManager.Close(sessionID); err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	return Result{Status: "success", Output: "closed"}
}

func (e *Executor) startPlaylist(ctx context.Context, payload map[string]interface{}) Result {
	if strings.TrimSpace(e.FPPBaseURL) == "" {
		return Result{Status: "error", Error: "fpp_base_url_missing"}
	}
	playlist, _ := payload["playlist"].(string)
	playlist = strings.TrimSpace(playlist)
	if playlist == "" {
		return Result{Status: "error", Error: "missing_playlist"}
	}
	attempts := []struct {
		Method string
		Path   string
		Query  map[string]string
		Body   interface{}
	}{
		{Method: http.MethodPost, Path: "/api/playlist/start", Body: map[string]string{"name": playlist}},
		{Method: http.MethodGet, Path: "/api/playlist/start", Query: map[string]string{"name": playlist}},
		{Method: http.MethodGet, Path: "/api/playlist/start", Query: map[string]string{"playlist": playlist}},
		{Method: http.MethodPost, Path: "/api/command", Body: map[string]interface{}{"command": "Start Playlist", "args": []string{playlist}}},
	}
	for _, attempt := range attempts {
		status, body, err := e.fppRequest(ctx, attempt.Method, attempt.Path, attempt.Query, attempt.Body)
		if err == nil && status >= 200 && status < 300 {
			return Result{Status: "success", Output: body}
		}
	}
	return Result{Status: "error", Error: "playlist_start_failed"}
}

func (e *Executor) stopPlaylist(ctx context.Context, payload map[string]interface{}) Result {
	if strings.TrimSpace(e.FPPBaseURL) == "" {
		return Result{Status: "error", Error: "fpp_base_url_missing"}
	}
	attempts := []struct {
		Method string
		Path   string
		Query  map[string]string
		Body   interface{}
	}{
		{Method: http.MethodPost, Path: "/api/playlist/stop"},
		{Method: http.MethodGet, Path: "/api/playlist/stop"},
		{Method: http.MethodPost, Path: "/api/command", Body: map[string]interface{}{"command": "Stop Playlist"}},
	}
	for _, attempt := range attempts {
		status, body, err := e.fppRequest(ctx, attempt.Method, attempt.Path, attempt.Query, attempt.Body)
		if err == nil && status >= 200 && status < 300 {
			return Result{Status: "success", Output: body}
		}
	}
	return Result{Status: "error", Error: "playlist_stop_failed"}
}

func (e *Executor) fppRequest(ctx context.Context, method string, path string, query map[string]string, body interface{}) (int, string, error) {
	base := strings.TrimRight(e.FPPBaseURL, "/")
	fullURL := base + path
	if len(query) > 0 {
		values := make([]string, 0, len(query))
		for key, value := range query {
			values = append(values, fmt.Sprintf("%s=%s", key, neturl.QueryEscape(value)))
		}
		fullURL = fullURL + "?" + strings.Join(values, "&")
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), nil
}

func (e *Executor) updateTunnelConfig(ctx context.Context, payload map[string]interface{}) Result {
	token, _ := payload["cloudflared_token"].(string)
	hostname, _ := payload["cloudflared_hostname"].(string)
	if strings.TrimSpace(token) == "" || strings.TrimSpace(hostname) == "" {
		return Result{Status: "error", Error: "missing_tunnel_fields"}
	}

	path := e.ConfigPath
	if strings.TrimSpace(path) == "" {
		path = "/home/fpp/media/config/fpp-monitor-agent.json"
	}
	cfg, err := config.Load(path)
	if err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	cfg.CloudflaredToken = token
	cfg.CloudflaredHostname = hostname
	if err := config.Save(path, cfg); err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	if e.SessionManager != nil {
		e.SessionManager.TunnelToken = token
		e.SessionManager.TunnelHostname = hostname
	}
	return Result{Status: "success", Output: "tunnel_config_applied"}
}

func (e *Executor) pluginUpdate(ctx context.Context, payload map[string]interface{}) Result {
	pluginID, _ := payload["plugin_id"].(string)
	if strings.TrimSpace(pluginID) == "" {
		pluginID = "showops-agent"
	}
	base := strings.TrimRight(e.FPPBaseURL, "/")
	if base == "" {
		base = "http://127.0.0.1"
	}
	updateURL := fmt.Sprintf("%s/api/plugin/%s/upgrade", base, pluginID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateURL, nil)
	if err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return Result{Status: "error", Error: "plugin_update_failed", Output: string(body)}
	}
	return Result{Status: "success", Output: string(body)}
}

func (e *Executor) pingHost(ctx context.Context, host string, timeout time.Duration) Result {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(secs), host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Result{Status: "error", Error: err.Error(), Output: string(out)}
	}
	return Result{Status: "success", Output: string(out)}
}

func (e *Executor) tcpProbe(ctx context.Context, host string, port int, timeout time.Duration) Result {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	conn.Close()
	return Result{Status: "success", Output: "tcp_ok"}
}

func (e *Executor) allowedTarget(host string, port int) bool {
	if !intInSlice(port, e.AllowPorts) {
		return false
	}
	ips, err := resolveHost(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if !ipAllowlisted(ip, e.AllowCIDRs) {
			return false
		}
	}
	return true
}

func resolveHost(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

func ipAllowlisted(ip net.IP, cidrs []string) bool {
	for _, c := range cidrs {
		_, netblock, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if netblock.Contains(ip) {
			return true
		}
	}
	return false
}

func intInSlice(val int, list []int) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}
