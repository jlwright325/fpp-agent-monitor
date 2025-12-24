package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

type Client struct {
	HTTP       *http.Client
	MaxRetries int
}

func New(timeout time.Duration) *Client {
	return &Client{
		HTTP: &http.Client{Timeout: timeout},
		// Retries apply only to transient transport failures.
		MaxRetries: 2,
	}
}

func (c *Client) DoWithRetry(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		req = req.Clone(ctx)
		resp, err := c.HTTP.Do(req)
		if err == nil {
			defer resp.Body.Close()
			b, rerr := io.ReadAll(resp.Body)
			if rerr != nil {
				return resp, nil, rerr
			}
			if resp.StatusCode >= 500 {
				lastErr = errors.New(resp.Status)
			} else {
				return resp, b, nil
			}
		} else {
			lastErr = err
		}
		if attempt < c.MaxRetries {
			backoff := time.Duration(1<<attempt) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
	}
	return nil, nil, lastErr
}
