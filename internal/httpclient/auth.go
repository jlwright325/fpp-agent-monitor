package httpclient

import (
	"net/http"
	"strings"
)

const deviceAuthHeader = "Authorization"

// AddDeviceAuth attaches the standard device auth header when token is present.
func AddDeviceAuth(req *http.Request, token string) (bool, int, string) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return false, 0, "missing"
	}
	req.Header.Set(deviceAuthHeader, "Bearer "+trimmed)
	return true, len(trimmed), "device_token"
}
