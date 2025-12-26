package httpclient

import "net/http"

const deviceAuthHeader = "Authorization"

// AddDeviceAuth attaches the standard device auth header when token is present.
func AddDeviceAuth(req *http.Request, token string) (bool, int) {
	if token == "" {
		return false, 0
	}
	req.Header.Set(deviceAuthHeader, "Bearer "+token)
	return true, len(token)
}
