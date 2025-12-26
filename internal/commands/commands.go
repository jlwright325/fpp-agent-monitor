package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"fpp-agent-monitor/internal/exec"
	"fpp-agent-monitor/internal/httpclient"
	"fpp-agent-monitor/internal/log"
)

type Runner struct {
	Client       *httpclient.Client
	Logger       *log.Logger
	APIBaseURL   string
	DeviceID     string
	DeviceToken  string
	AgentVersion string
	Interval     time.Duration
	MaxBackoff   time.Duration
	Executor     *exec.Executor
	DebugHTTP    bool
	DryRun       bool
}

type command struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	IssuedAt  string                 `json:"issued_at"`
	ExpiresAt string                 `json:"expires_at"`
}

type response struct {
	Commands []command `json:"commands"`
}

func (r *Runner) Run(ctx context.Context) error {
	backoff := r.Interval
	for {
		if ctx.Err() != nil {
			return nil
		}
		cmds, err := r.poll(ctx)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				return ErrUnauthorized
			}
			r.Logger.Warn("command_poll_failed", map[string]interface{}{"error": err.Error()})
			if backoff < r.MaxBackoff {
				backoff *= 2
				if backoff > r.MaxBackoff {
					backoff = r.MaxBackoff
				}
			}
			sleep(ctx, backoff)
			continue
		}
		backoff = r.Interval
		for _, cmd := range cmds {
			if ctx.Err() != nil {
				return nil
			}
			r.handleCommand(ctx, cmd)
		}
		sleep(ctx, r.Interval)
	}
}

func (r *Runner) poll(ctx context.Context) ([]command, error) {
	q := url.Values{}
	q.Set("device_id", r.DeviceID)
	q.Set("agent_version", r.AgentVersion)
	url := r.APIBaseURL + "/v1/agent/commands?" + q.Encode()
	path := "/v1/agent/commands"
	r.Logger.Info("command_poll_request", map[string]interface{}{"path": path})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	authSet, tokenLen, tokenSource := httpclient.AddDeviceAuth(req, r.DeviceToken)
	r.Logger.Info("command_poll_auth", map[string]interface{}{
		"auth_set":  authSet,
		"header":    "Authorization",
		"token_len": tokenLen,
		"source":    tokenSource,
		"device_id": r.DeviceID,
		"path":      path,
	})
	if r.DebugHTTP {
		r.Logger.Info("command_poll_http", map[string]interface{}{
			"method":      http.MethodGet,
			"url":         url,
			"path":        path,
			"auth_scheme": authScheme(authSet),
		})
	}
	if r.DryRun {
		r.Logger.Info("command_poll_dry_run", map[string]interface{}{"path": path})
		return nil, nil
	}

	resp, body, err := r.Client.DoWithRetry(ctx, req)
	if err != nil {
		return nil, err
	}
	r.Logger.Info("command_poll_response", map[string]interface{}{
		"status_code": resp.StatusCode,
		"path":        path,
	})
	if resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized {
			r.Logger.Warn("device_token_invalid", map[string]interface{}{
				"status_code": resp.StatusCode,
				"body":        truncateBody(body, 2048),
				"path":        path,
			})
			return nil, ErrUnauthorized
		}
		r.Logger.Warn("command_poll_http_error", map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        truncateBody(body, 2048),
			"path":        path,
		})
		return nil, statusError(resp.StatusCode)
	}
	var out response
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}

func (r *Runner) handleCommand(ctx context.Context, cmd command) {
	started := time.Now().Unix()
	result := r.Executor.Execute(ctx, cmd.Type, cmd.Payload)
	finished := time.Now().Unix()

	payload := map[string]interface{}{
		"command_id":  cmd.ID,
		"status":      result.Status,
		"started_at":  started,
		"finished_at": finished,
		"output":      result.Output,
		"error":       result.Error,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		r.Logger.Error("command_result_marshal_failed", map[string]interface{}{"command_id": cmd.ID, "error": err.Error()})
		return
	}
	url := r.APIBaseURL + "/v1/agent/command-results"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		r.Logger.Error("command_result_request_failed", map[string]interface{}{"command_id": cmd.ID, "error": err.Error()})
		return
	}
	authSet, tokenLen, tokenSource := httpclient.AddDeviceAuth(req, r.DeviceToken)
	r.Logger.Info("command_result_auth", map[string]interface{}{
		"auth_set":  authSet,
		"header":    "Authorization",
		"token_len": tokenLen,
		"source":    tokenSource,
		"device_id": r.DeviceID,
		"path":      "/v1/agent/command-results",
	})
	if r.DebugHTTP {
		r.Logger.Info("command_result_http", map[string]interface{}{
			"method":      http.MethodPost,
			"url":         r.APIBaseURL + "/v1/agent/command-results",
			"path":        "/v1/agent/command-results",
			"auth_scheme": authScheme(authSet),
		})
	}
	if r.DryRun {
		r.Logger.Info("command_result_dry_run", map[string]interface{}{"command_id": cmd.ID})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, _, err := r.Client.DoWithRetry(ctx, req)
	if err != nil {
		r.Logger.Warn("command_result_send_failed", map[string]interface{}{"command_id": cmd.ID, "error": err.Error()})
	} else if resp.StatusCode >= 300 {
		r.Logger.Warn("command_result_send_failed", map[string]interface{}{"command_id": cmd.ID, "status": resp.StatusCode})
	}

	if result.ShouldExit {
		r.Logger.Info("agent_exiting_on_command", map[string]interface{}{"command_id": cmd.ID, "type": cmd.Type})
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

type statusError int

func (s statusError) Error() string { return "http_status_" + strconv.Itoa(int(s)) }

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
