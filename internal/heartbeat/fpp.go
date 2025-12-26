package heartbeat

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"fpp-agent-monitor/internal/httpclient"
)

func fetchFPPState(ctx context.Context, baseURL string, client *httpclient.Client) (*string, stateInfo, resourcesPayload) {
	var version *string
	state := stateInfo{}
	resources := resourcesPayload{}

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
		if cpu := findFloat(statusMap, "cpu", "CPU", "cpu_percent"); cpu != nil {
			resources.CPUPercent = cpu
		}
		if mem := findFloat(statusMap, "memory", "Memory", "mem_percent"); mem != nil {
			resources.MemoryPercent = mem
		}
		if disk := findDiskFreeMB(statusMap); disk != nil {
			resources.DiskFreeMB = disk
		}
	}
	return version, state, resources
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

func findFloat(data map[string]interface{}, keys ...string) *float64 {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			if f := coerceFloat(v); f != nil {
				return f
			}
		}
	}
	for k, v := range data {
		for _, key := range keys {
			if strings.EqualFold(k, key) {
				if f := coerceFloat(v); f != nil {
					return f
				}
			}
		}
	}
	if util, ok := pickMap(data, "utilization", "Utilization"); ok {
		for _, key := range keys {
			if f := findFloat(util, key); f != nil {
				return f
			}
		}
	}
	return nil
}

func findDiskFreeMB(data map[string]interface{}) *float64 {
	if v := findFloat(data, "disk_free_mb", "DiskFreeMB"); v != nil {
		return v
	}
	util, ok := pickMap(data, "utilization", "Utilization")
	if !ok {
		return nil
	}
	disk, ok := pickMap(util, "disk", "Disk")
	if !ok {
		return nil
	}
	root, ok := pickMap(disk, "root", "Root")
	if !ok {
		root, ok = pickMap(disk, "media", "Media")
		if !ok {
			return nil
		}
	}
	free := findFloat(root, "free", "Free")
	if free == nil {
		return nil
	}
	value := *free
	if value > 1024*1024 {
		value = value / (1024 * 1024)
	}
	return &value
}

func pickMap(data map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				return m, true
			}
		}
	}
	for k, v := range data {
		for _, key := range keys {
			if strings.EqualFold(k, key) {
				if m, ok := v.(map[string]interface{}); ok {
					return m, true
				}
			}
		}
	}
	return nil, false
}

func coerceFloat(value interface{}) *float64 {
	switch v := value.(type) {
	case float64:
		return &v
	case float32:
		out := float64(v)
		return &out
	case int:
		out := float64(v)
		return &out
	case int64:
		out := float64(v)
		return &out
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return &f
		}
	}
	return nil
}
