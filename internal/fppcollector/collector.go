package fppcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"fpp-agent-monitor/internal/httpclient"
	"fpp-agent-monitor/internal/log"
)

type Collector struct {
	Client      *httpclient.Client
	Logger      *log.Logger
	APIBaseURL  string
	DeviceID    string
	DeviceToken string
	FPPBaseURL  string
	Interval    time.Duration
	MaxBackoff  time.Duration
	DebugHTTP   bool
	DryRun      bool
}

type endpointSpec struct {
	Path     string
	Interval time.Duration
	MaxBytes int
}

type snapshot struct {
	Endpoint   string `json:"endpoint"`
	StatusCode int    `json:"status_code,omitempty"`
	CapturedAt int64  `json:"captured_at,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Payload    string `json:"payload,omitempty"`
}

type batchPayload struct {
	PayloadVersion int64      `json:"payload_version"`
	CapturedAt     int64      `json:"captured_at"`
	DeviceID       string     `json:"device_id,omitempty"`
	Snapshots      []snapshot `json:"snapshots"`
}

const defaultMaxBytes = 256 * 1024

var endpoints = []endpointSpec{
	{Path: "/api/system/status", Interval: 60 * time.Second},
	{Path: "/api/player", Interval: 60 * time.Second},
	{Path: "/api/playlist/status", Interval: 60 * time.Second},
	{Path: "/api/sequence/status", Interval: 60 * time.Second},
	{Path: "/api/system/info", Interval: 30 * time.Minute},
	{Path: "/api/system/version", Interval: 30 * time.Minute},
	{Path: "/api/scheduler", Interval: 30 * time.Minute},
	{Path: "/api/schedule", Interval: 30 * time.Minute},
	{Path: "/api/playlist/schedule", Interval: 30 * time.Minute},
	{Path: "/api/playlists/schedule", Interval: 30 * time.Minute},
	{Path: "/api/playlists", Interval: 60 * time.Minute},
	{Path: "/api/sequences", Interval: 60 * time.Minute},
	{Path: "/api/media", Interval: 60 * time.Minute},
	{Path: "/api/network", Interval: 30 * time.Minute},
	{Path: "/api/network/wifi", Interval: 30 * time.Minute},
	{Path: "/api/channel/output/universeOutputs", Interval: 30 * time.Minute, MaxBytes: 1024 * 1024},
	{Path: "/api/plugin", Interval: 60 * time.Minute},
	{Path: "/api/plugin/showops-agent/updates", Interval: 30 * time.Minute},
	{Path: "/api/logs/fppd", Interval: 60 * time.Minute, MaxBytes: 128 * 1024},
	{Path: "/api/logs/system", Interval: 60 * time.Minute, MaxBytes: 128 * 1024},
	{Path: "/api/settings", Interval: 60 * time.Minute},
}

func (c *Collector) Run(ctx context.Context) error {
	if c.Interval <= 0 {
		c.Interval = 60 * time.Second
	}
	backoff := c.Interval
	lastFetched := map[string]time.Time{}

	for {
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		var batch []snapshot

		for _, ep := range endpoints {
			nextAt := lastFetched[ep.Path].Add(ep.Interval)
			if !lastFetched[ep.Path].IsZero() && now.Before(nextAt) {
				continue
			}
			snap := c.fetchEndpoint(ctx, ep)
			lastFetched[ep.Path] = now
			batch = append(batch, snap)
		}

		if len(batch) == 0 {
			sleep(ctx, c.Interval)
			continue
		}

		if err := c.sendBatch(ctx, batch); err != nil {
			c.Logger.Warn("fpp_collect_failed", map[string]interface{}{"error": err.Error()})
			if backoff < c.MaxBackoff {
				backoff *= 2
				if backoff > c.MaxBackoff {
					backoff = c.MaxBackoff
				}
			}
			sleep(ctx, backoff)
			continue
		}
		backoff = c.Interval
		sleep(ctx, c.Interval)
	}
}

func (c *Collector) fetchEndpoint(ctx context.Context, ep endpointSpec) snapshot {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := c.FPPBaseURL + ep.Path
	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, url, nil)
	if err != nil {
		return snapshot{Endpoint: ep.Path, StatusCode: 0, CapturedAt: time.Now().Unix()}
	}
	resp, body, err := c.Client.DoWithRetry(timeoutCtx, req)
	if err != nil {
		return snapshot{Endpoint: ep.Path, StatusCode: 0, CapturedAt: time.Now().Unix()}
	}

	maxBytes := ep.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	truncated := false
	if len(body) > maxBytes {
		body = body[:maxBytes]
		truncated = true
	}

	return snapshot{
		Endpoint:   ep.Path,
		StatusCode: resp.StatusCode,
		CapturedAt: time.Now().Unix(),
		Truncated:  truncated,
		Payload:    string(body),
	}
}

func (c *Collector) sendBatch(ctx context.Context, snaps []snapshot) error {
	payload := batchPayload{
		PayloadVersion: 1,
		CapturedAt:     time.Now().Unix(),
		DeviceID:       c.DeviceID,
		Snapshots:      snaps,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := c.APIBaseURL + "/v1/ingest/fpp"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	authSet, tokenLen, tokenSource := httpclient.AddDeviceAuth(req, c.DeviceToken)
	c.Logger.Info("fpp_collect_auth", map[string]interface{}{
		"auth_set":  authSet,
		"header":    "Authorization",
		"token_len": tokenLen,
		"source":    tokenSource,
		"path":      "/v1/ingest/fpp",
	})
	req.Header.Set("Content-Type", "application/json")
	if c.DryRun {
		c.Logger.Info("fpp_collect_dry_run", map[string]interface{}{"path": "/v1/ingest/fpp"})
		return nil
	}
	resp, body, err := c.Client.DoWithRetry(ctx, req)
	if err != nil {
		return err
	}
	c.Logger.Info("fpp_collect_response", map[string]interface{}{
		"status_code": resp.StatusCode,
		"path":        "/v1/ingest/fpp",
	})
	if resp.StatusCode >= 300 {
		c.Logger.Warn("fpp_collect_http_error", map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        truncateBody(body, 2048),
			"path":        "/v1/ingest/fpp",
		})
		return httpStatusError(resp.StatusCode)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func truncateBody(body []byte, max int) string {
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max])
}

func httpStatusError(code int) error {
	return &statusError{Code: code}
}

type statusError struct{ Code int }

func (e *statusError) Error() string { return "http_status_" + strconv.Itoa(e.Code) }
