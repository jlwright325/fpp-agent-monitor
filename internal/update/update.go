package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fpp-agent-monitor/internal/log"
)

type Params struct {
	URL          string
	SHA256       string
	DownloadDir  string
	BinaryPath   string
	AllowFileExt bool
}

func Apply(ctx context.Context, logger *log.Logger, p Params) error {
	if p.URL == "" || p.SHA256 == "" {
		return errors.New("missing_update_params")
	}
	if err := os.MkdirAll(p.DownloadDir, 0755); err != nil {
		return err
	}
	tmpPath := filepath.Join(p.DownloadDir, "agent-download.tmp")
	if err := download(ctx, p.URL, tmpPath); err != nil {
		return err
	}
	sum, err := sha256File(tmpPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, p.SHA256) {
		return errors.New("sha256_mismatch")
	}
	newPath := p.BinaryPath + ".new"
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, newPath); err != nil {
		return err
	}
	if err := os.Rename(newPath, p.BinaryPath); err != nil {
		return err
	}
	if logger != nil {
		logger.Info("agent_updated", map[string]interface{}{"binary": p.BinaryPath})
	}
	return nil
}

func download(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("download_failed")
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
