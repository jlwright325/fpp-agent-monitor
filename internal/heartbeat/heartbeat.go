package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"fpp-agent-monitor/internal/httpclient"
	"fpp-agent-monitor/internal/log"
)

type Sender struct {
	Client          *httpclient.Client
	Logger          *log.Logger
	APIBaseURL      string
	DeviceID        string
	DeviceToken     string
	AgentVersion    string
	FPPBaseURL      string
	Interval        time.Duration
	IdleInterval    time.Duration
	PlayingInterval time.Duration
	ErrorInterval   time.Duration
	ErrorBurst      time.Duration
	CheckInterval   time.Duration
	MaxBackoff      time.Duration
	DebugHTTP       bool
	DryRun          bool
}

type payload struct {
	PayloadVersion int64            `json:"payload_version"`
	SentAt         int64            `json:"sent_at"`
	Device         deviceInfo       `json:"device"`
	State          stateInfo        `json:"state"`
	Resources      resourcesPayload `json:"resources"`
}

type deviceInfo struct {
	DeviceID     string  `json:"device_id"`
	Hostname     string  `json:"hostname"`
	FPPVersion   *string `json:"fpp_version"`
	AgentVersion string  `json:"agent_version"`
}

type stateInfo struct {
	Playing  *bool   `json:"playing"`
	Mode     *string `json:"mode"`
	Playlist *string `json:"playlist"`
	Sequence *string `json:"sequence"`
}

type resourcesPayload struct {
	CPUPercent    *float64 `json:"cpu_percent"`
	MemoryPercent *float64 `json:"memory_percent"`
	DiskFreeMB    *float64 `json:"disk_free_mb"`
}

func (s *Sender) Run(ctx context.Context) error {
	checkInterval := s.CheckInterval
	if checkInterval <= 0 {
		if s.PlayingInterval > 0 {
			checkInterval = s.PlayingInterval
		} else if s.Interval > 0 {
			checkInterval = s.Interval
		} else {
			checkInterval = 60 * time.Second
		}
	}
	idleInterval := s.IdleInterval
	if idleInterval <= 0 {
		idleInterval = 30 * time.Minute
	}
	playingInterval := s.PlayingInterval
	if playingInterval <= 0 {
		playingInterval = 60 * time.Second
	}
	errorInterval := s.ErrorInterval
	if errorInterval <= 0 {
		errorInterval = 15 * time.Second
	}
	errorBurst := s.ErrorBurst
	if errorBurst <= 0 {
		errorBurst = 2 * time.Minute
	}

	backoff := checkInterval
	var lastSent time.Time
	var lastPlaying bool
	var lastPlayingSet bool
	var errorBurstUntil time.Time

	for {
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		fppVersion, state, resources, stateOK := fetchFPPState(ctx, s.FPPBaseURL, s.Client)

		playing := false
		stateChanged := false
		if state.Playing != nil {
			playing = *state.Playing
			if lastPlayingSet && playing != lastPlaying {
				stateChanged = true
			}
			lastPlaying = playing
			lastPlayingSet = true
		}

		interval := idleInterval
		if playing {
			interval = playingInterval
		}
		if now.Before(errorBurstUntil) {
			interval = errorInterval
		}
		if !stateOK && errorBurst > 0 {
			errorBurstUntil = now.Add(errorBurst)
			interval = errorInterval
		}

		shouldSend := lastSent.IsZero() || stateChanged || now.Sub(lastSent) >= interval
		if shouldSend {
			if err := s.sendOnce(ctx, fppVersion, state, resources); err != nil {
				if errors.Is(err, ErrUnauthorized) {
					return ErrUnauthorized
				}
				s.Logger.Warn("heartbeat_failed", map[string]interface{}{"error": err.Error()})
				if errorBurst > 0 {
					errorBurstUntil = now.Add(errorBurst)
				}
				if backoff < s.MaxBackoff {
					backoff *= 2
					if backoff > s.MaxBackoff {
						backoff = s.MaxBackoff
					}
				}
				sleep(ctx, backoff)
				continue
			}
			lastSent = now
			backoff = checkInterval
		}

		nextDelay := checkInterval
		if !lastSent.IsZero() && interval > 0 {
			remaining := time.Until(lastSent.Add(interval))
			if remaining > 0 && remaining < nextDelay {
				nextDelay = remaining
			}
		}
		sleep(ctx, nextDelay)
	}
}

func (s *Sender) sendOnce(ctx context.Context, fppVersion *string, state stateInfo, resources resourcesPayload) error {
	hostname, _ := os.Hostname()

	s.Logger.Info("heartbeat_request", map[string]interface{}{"path": "/v1/ingest/heartbeat"})
	p := payload{
		PayloadVersion: 1,
		SentAt:         time.Now().Unix(),
		Device: deviceInfo{
			DeviceID:     s.DeviceID,
			Hostname:     hostname,
			FPPVersion:   fppVersion,
			AgentVersion: s.AgentVersion,
		},
		State:     state,
		Resources: resources,
	}

	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	url := s.APIBaseURL + "/v1/ingest/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	authSet, tokenLen, tokenSource := httpclient.AddDeviceAuth(req, s.DeviceToken)
	s.Logger.Info("heartbeat_auth", map[string]interface{}{
		"auth_set":  authSet,
		"header":    "Authorization",
		"token_len": tokenLen,
		"source":    tokenSource,
		"device_id": s.DeviceID,
		"path":      "/v1/ingest/heartbeat",
	})
	if s.DebugHTTP {
		s.Logger.Info("heartbeat_request", map[string]interface{}{
			"method":      http.MethodPost,
			"url":         url,
			"path":        "/v1/ingest/heartbeat",
			"auth_scheme": authScheme(authSet),
		})
	}
	req.Header.Set("Content-Type", "application/json")
	if s.DryRun {
		s.Logger.Info("heartbeat_dry_run", map[string]interface{}{"path": "/v1/ingest/heartbeat"})
		return nil
	}
	resp, body, err := s.Client.DoWithRetry(ctx, req)
	if err != nil {
		return err
	}
	s.Logger.Info("heartbeat_response", map[string]interface{}{
		"status_code": resp.StatusCode,
		"path":        "/v1/ingest/heartbeat",
	})
	if resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized {
			s.Logger.Warn("device_token_invalid", map[string]interface{}{
				"status_code": resp.StatusCode,
				"body":        truncateBody(body, 2048),
				"path":        "/v1/ingest/heartbeat",
			})
			return ErrUnauthorized
		}
		s.Logger.Warn("heartbeat_http_error", map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        truncateBody(body, 2048),
			"path":        "/v1/ingest/heartbeat",
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

func httpStatusError(code int) error {
	return &statusError{Code: code}
}

type statusError struct{ Code int }

func (e *statusError) Error() string { return "http_status_" + strconv.Itoa(e.Code) }

func truncateBody(body []byte, max int) string {
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max])
}

func authScheme(authSet bool) string {
	if authSet {
		return "bearer"
	}
	return "none"
}

var ErrUnauthorized = errors.New("unauthorized")
