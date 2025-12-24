package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"fpp-monitor-agent/internal/httpclient"
	"fpp-monitor-agent/internal/log"
)

type Enroller struct {
	Client       *httpclient.Client
	Logger       *log.Logger
	APIBaseURL   string
	AgentVersion string
	Token        string
	MaxBackoff   time.Duration
}

type requestPayload struct {
	EnrollmentToken string   `json:"enrollment_token"`
	Hostname        string   `json:"hostname"`
	Arch            string   `json:"arch"`
	AgentVersion    string   `json:"agent_version"`
	Capabilities    []string `json:"capabilities"`
}

type responsePayload struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	LocationID  string `json:"location_id"`
}

func (e *Enroller) Run(ctx context.Context) (*responsePayload, error) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		resp, err := e.enrollOnce(ctx)
		if err == nil {
			return resp, nil
		}
		e.Logger.Warn("enroll_failed", map[string]interface{}{"error": err.Error()})
		if backoff < e.MaxBackoff {
			backoff *= 2
			if backoff > e.MaxBackoff {
				backoff = e.MaxBackoff
			}
		}
		sleep(ctx, backoff)
	}
}

func (e *Enroller) enrollOnce(ctx context.Context) (*responsePayload, error) {
	hostname, _ := os.Hostname()
	payload := requestPayload{
		EnrollmentToken: e.Token,
		Hostname:        hostname,
		Arch:            runtime.GOARCH,
		AgentVersion:    e.AgentVersion,
		Capabilities: []string{
			"heartbeat",
			"commands",
			"update",
			"network_probe",
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := e.APIBaseURL + "/v1/agent/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, body, err := e.Client.DoWithRetry(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, statusError(resp.StatusCode)
	}
	var out responsePayload
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.DeviceID == "" || out.DeviceToken == "" {
		return nil, errInvalidResponse
	}
	return &out, nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

type statusError int

func (s statusError) Error() string { return "http_status_" + strconv.Itoa(int(s)) }

var errInvalidResponse = errors.New("invalid_enroll_response")
