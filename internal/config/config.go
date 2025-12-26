package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	APIBaseURL             string           `json:"api_base_url"`
	EnrollmentToken        string           `json:"enrollment_token"`
	DeviceToken            string           `json:"device_token"`
	DeviceID               string           `json:"device_id"`
	LocationID             string           `json:"location_id"`
	Label                  string           `json:"label"`
	HeartbeatIntervalSec   int              `json:"heartbeat_interval_sec"`
	CommandPollIntervalSec int              `json:"command_poll_interval_sec"`
	FPPCollectEnabled      *bool            `json:"fpp_collect_enabled"`
	FPPCollectIntervalSec  int              `json:"fpp_collect_interval_sec"`
	FPPBaseURL             string           `json:"fpp_base_url"`
	Update                 UpdateConfig     `json:"update"`
	NetworkAllowlist       NetworkAllowlist `json:"network_allowlist"`
	RebootEnabled          bool             `json:"reboot_enabled"`
	RestartFPPCommand      string           `json:"restart_fpp_command"`
}

type UpdateConfig struct {
	Enabled        bool   `json:"enabled"`
	Channel        string `json:"channel"`
	AllowDowngrade bool   `json:"allow_downgrade"`
}

type NetworkAllowlist struct {
	CIDRs []string `json:"cidrs"`
	Ports []int    `json:"ports"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	applyEnvOverrides(&cfg)
	setDefaults(&cfg)
	normalize(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "config.json.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(info.Mode()); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func applyEnvOverrides(cfg *Config) {
	if v := strings.TrimSpace(os.Getenv("SHOWOPS_API_BASE_URL")); v != "" {
		cfg.APIBaseURL = v
		return
	}
	if v := strings.TrimSpace(os.Getenv("FPP_MONITOR_API_BASE_URL")); v != "" {
		cfg.APIBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("FPP_MONITOR_DEVICE_TOKEN")); v != "" {
		cfg.DeviceToken = v
	}
	if v := strings.TrimSpace(os.Getenv("FPP_MONITOR_DEVICE_ID")); v != "" {
		cfg.DeviceID = v
	}
}

func setDefaults(cfg *Config) {
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://api.showops.io"
	}
	if cfg.HeartbeatIntervalSec <= 0 {
		cfg.HeartbeatIntervalSec = 15
	}
	if cfg.CommandPollIntervalSec <= 0 {
		cfg.CommandPollIntervalSec = 7
	}
	if cfg.FPPCollectIntervalSec <= 0 {
		cfg.FPPCollectIntervalSec = 15
	}
	if cfg.FPPBaseURL == "" {
		cfg.FPPBaseURL = "http://127.0.0.1"
	}
	if cfg.RestartFPPCommand == "" {
		cfg.RestartFPPCommand = "systemctl restart fpp"
	}
	if cfg.FPPCollectEnabled == nil {
		enabled := true
		cfg.FPPCollectEnabled = &enabled
	}
}

func validate(cfg *Config) error {
	if cfg.APIBaseURL == "" {
		return errors.New("api_base_url is required")
	}
	if cfg.DeviceToken != "" && cfg.DeviceID == "" {
		return errors.New("device_id is required when device_token is set")
	}
	return nil
}

func normalize(cfg *Config) {
	cfg.APIBaseURL = strings.TrimSpace(cfg.APIBaseURL)
	cfg.EnrollmentToken = strings.TrimSpace(cfg.EnrollmentToken)
	cfg.DeviceToken = strings.TrimSpace(cfg.DeviceToken)
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	cfg.LocationID = strings.TrimSpace(cfg.LocationID)
	cfg.Label = strings.TrimSpace(cfg.Label)
}
