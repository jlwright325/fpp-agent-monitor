package heartbeat

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"fpp-monitor-agent/internal/httpclient"
)

func fetchFPPState(ctx context.Context, baseURL string, client *httpclient.Client) (*string, stateInfo) {
	var version *string
	state := stateInfo{}

	infoURL := baseURL + "/api/system/info"
	if v := fetchStringField(ctx, client, infoURL, []string{"version", "fppd"}); v != "" {
		version = &v
	}

	statusURL := baseURL + "/api/system/status"
	statusMap := fetchJSON(ctx, client, statusURL)
	if statusMap != nil {
		if b, ok := statusMap["playing"].(bool); ok {
			state.Playing = &b
		}
		if b, ok := statusMap["currently_playing"].(bool); ok {
			state.Playing = &b
		}
		if s, ok := statusMap["mode"].(string); ok && s != "" {
			state.Mode = &s
		}
		if s, ok := statusMap["playlist"].(string); ok && s != "" {
			state.Playlist = &s
		}
		if s, ok := statusMap["sequence"].(string); ok && s != "" {
			state.Sequence = &s
		}
	}
	return version, state
}

func fetchStringField(ctx context.Context, client *httpclient.Client, url string, keys []string) string {
	data := fetchJSON(ctx, client, url)
	if data == nil {
		return ""
	}
	for _, key := range keys {
		if v, ok := data[key].(string); ok {
			return v
		}
	}
	return ""
}

func fetchJSON(ctx context.Context, client *httpclient.Client, url string) map[string]interface{} {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, body, err := client.DoWithRetry(ctx, req)
	if err != nil || resp.StatusCode >= 300 {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}
	return out
}
