package pairing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"fpp-agent-monitor/internal/httpclient"
	"fpp-agent-monitor/internal/log"
)

type Requester struct {
	Client            *httpclient.Client
	Logger            *log.Logger
	APIBaseURL        string
	DeviceFingerprint string
	AgentVersion      string
	FPPBaseURL        string
	MaxBackoff        time.Duration
	DebugHTTP         bool
	DryRun            bool
}

type CreateResponse struct {
	PairingCode string `json:"pairing_code"`
	ExpiresAt   string `json:"expires_at"`
	RequestID   string `json:"request_id"`
}

type StatusResponse struct {
	Status  string         `json:"status"`
	Claimed *ClaimedStatus `json:"claimed,omitempty"`
}

type ClaimedStatus struct {
	DeviceID   string      `json:"device_id"`
	Credential *Credential `json:"credential,omitempty"`
}

type Credential struct {
	CredentialID string `json:"credential_id"`
	Token        string `json:"token"`
}

type requestPayload struct {
	DeviceFingerprint string      `json:"device_fingerprint"`
	DeviceInfo        *deviceInfo `json:"device_info,omitempty"`
}

type deviceInfo struct {
	Hostname   string `json:"hostname,omitempty"`
	FPPVersion string `json:"fpp_version,omitempty"`
	Platform   string `json:"platform,omitempty"`
	Model      string `json:"model,omitempty"`
}

type fppInfo struct {
	Hostname string
	Version  string
	Platform string
	Variant  string
}

func (r *Requester) CreateRequest(ctx context.Context) (*CreateResponse, error) {
	if strings.TrimSpace(r.DeviceFingerprint) == "" {
		return nil, errors.New("device_fingerprint_missing")
	}
	info := buildDeviceInfo(ctx, r.FPPBaseURL, r.Client)
	payload := requestPayload{
		DeviceFingerprint: strings.TrimSpace(r.DeviceFingerprint),
		DeviceInfo:        info,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := r.APIBaseURL + "/v1/pairing/requests"
	if r.DebugHTTP {
		r.Logger.Info("pairing_http", map[string]interface{}{
			"method":      http.MethodPost,
			"url":         url,
			"path":        "/v1/pairing/requests",
			"auth_scheme": "none",
		})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.DryRun {
		r.Logger.Info("pairing_create_dry_run", map[string]interface{}{"path": "/v1/pairing/requests"})
		return nil, errors.New("dry_run")
	}
	resp, respBody, err := r.Client.DoWithRetry(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		r.Logger.Warn("pairing_create_error", map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        truncateBody(respBody, 300),
			"path":        "/v1/pairing/requests",
		})
		return nil, statusError(resp.StatusCode)
	}
	var out CreateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	if out.RequestID == "" || out.PairingCode == "" {
		return nil, errors.New("invalid_pairing_response")
	}
	return &out, nil
}

func (r *Requester) FetchStatus(ctx context.Context, requestID string) (*StatusResponse, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, errors.New("pairing_request_id_missing")
	}
	url := r.APIBaseURL + "/v1/pairing/requests/" + requestID
	if r.DebugHTTP {
		r.Logger.Info("pairing_http", map[string]interface{}{
			"method":      http.MethodGet,
			"url":         url,
			"path":        "/v1/pairing/requests/:id",
			"auth_scheme": "none",
		})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if r.DryRun {
		r.Logger.Info("pairing_status_dry_run", map[string]interface{}{"path": "/v1/pairing/requests/:id"})
		return nil, errors.New("dry_run")
	}
	resp, body, err := r.Client.DoWithRetry(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		r.Logger.Warn("pairing_status_error", map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        truncateBody(body, 300),
			"path":        "/v1/pairing/requests/:id",
		})
		return nil, statusError(resp.StatusCode)
	}
	var out StatusResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.Status == "" {
		return nil, errors.New("invalid_pairing_status")
	}
	return &out, nil
}

func ComputeFingerprint() (string, error) {
	var parts []string
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if v := readTrimmed(path); v != "" {
			parts = append(parts, "mid:"+v)
			break
		}
	}
	ifaces, _ := net.Interfaces()
	sort.SliceStable(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.HardwareAddr == nil || len(iface.HardwareAddr) == 0 {
			continue
		}
		if isIgnoredIface(iface.Name) {
			continue
		}
		parts = append(parts, "mac:"+strings.ToLower(iface.HardwareAddr.String()))
	}
	if len(parts) == 0 {
		return "", errors.New("fingerprint_sources_missing")
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:]), nil
}

func isIgnoredIface(name string) bool {
	ignorePrefixes := []string{"lo", "docker", "veth", "br-", "tun", "tap", "wg", "zt", "tailscale"}
	for _, prefix := range ignorePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func readTrimmed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func buildDeviceInfo(ctx context.Context, baseURL string, client *httpclient.Client) *deviceInfo {
	info := deviceInfo{
		Hostname: fallbackHostname(),
		Platform: runtime.GOARCH,
	}
	fpp := fetchFPPInfo(ctx, baseURL, client)
	if fpp.Hostname != "" {
		info.Hostname = fpp.Hostname
	}
	if fpp.Version != "" {
		info.FPPVersion = fpp.Version
	}
	if fpp.Platform != "" {
		info.Platform = fpp.Platform
	}
	if fpp.Variant != "" {
		info.Model = fpp.Variant
	}
	if info.Hostname == "" && info.FPPVersion == "" && info.Platform == "" && info.Model == "" {
		return nil
	}
	return &info
}

func fallbackHostname() string {
	host, _ := os.Hostname()
	return strings.TrimSpace(host)
}

func fetchFPPInfo(ctx context.Context, baseURL string, client *httpclient.Client) fppInfo {
	if baseURL == "" || client == nil {
		return fppInfo{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/system/info", nil)
	if err != nil {
		return fppInfo{}
	}
	resp, body, err := client.DoWithRetry(ctx, req)
	if err != nil || resp.StatusCode >= 300 {
		return fppInfo{}
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return fppInfo{}
	}
	return fppInfo{
		Hostname: pickString(out, "HostName", "hostname"),
		Version:  pickString(out, "Version", "version", "fppd"),
		Platform: pickString(out, "Platform", "platform"),
		Variant:  pickString(out, "Variant", "variant", "SubPlatform", "subplatform"),
	}
}

func pickString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type statusError int

func (s statusError) Error() string { return "http_status_" + strconv.Itoa(int(s)) }

func truncateBody(body []byte, max int) string {
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max])
}
