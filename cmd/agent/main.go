package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"fpp-agent-monitor/internal/commands"
	"fpp-agent-monitor/internal/config"
	"fpp-agent-monitor/internal/enroll"
	"fpp-agent-monitor/internal/exec"
	"fpp-agent-monitor/internal/heartbeat"
	"fpp-agent-monitor/internal/httpclient"
	"fpp-agent-monitor/internal/log"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "config path")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		os.Stdout.WriteString(version + "\n")
		return
	}

	logger := &log.Logger{}
	host, _ := os.Hostname()
	logger.Info("agent_start", map[string]interface{}{"version": version, "hostname": host})

	resolvedPath, checked := resolveConfigPath(*configPath)
	if resolvedPath == "" {
		logger.Error("config_missing", map[string]interface{}{"checked_paths": checked})
		os.Exit(1)
	}
	logger.Info("config_selected", map[string]interface{}{"path": resolvedPath})

	cfg, err := config.Load(resolvedPath)
	if err != nil {
		logger.Error("config_load_failed", map[string]interface{}{"error": err.Error(), "path": resolvedPath})
		os.Exit(1)
	}

	httpClient := httpclient.New(10 * time.Second)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.DeviceToken == "" && cfg.EnrollmentToken != "" {
		logger.Info("enrollment_start", map[string]interface{}{"api_base_url": cfg.APIBaseURL})
		enroller := &enroll.Enroller{
			Client:       httpClient,
			Logger:       logger,
			APIBaseURL:   cfg.APIBaseURL,
			AgentVersion: version,
			Token:        cfg.EnrollmentToken,
			Label:        cfg.Label,
			FPPBaseURL:   cfg.FPPBaseURL,
			MaxBackoff:   60 * time.Second,
		}
		resp, err := enroller.Run(ctx)
		if err != nil {
			logger.Error("enrollment_failed", map[string]interface{}{"error": err.Error()})
			os.Exit(1)
		}
		cfg.DeviceID = resp.DeviceID
		cfg.DeviceToken = resp.DeviceToken
		cfg.LocationID = resp.LocationID
		if resp.Label != "" {
			cfg.Label = resp.Label
		}
		cfg.EnrollmentToken = ""
		if err := config.Save(resolvedPath, cfg); err != nil {
			logger.Error("config_write_failed", map[string]interface{}{"error": err.Error(), "path": resolvedPath})
			os.Exit(1)
		}
		logger.Info("enrollment_success", map[string]interface{}{"device_id": cfg.DeviceID})
	}

	executor := &exec.Executor{
		Logger:            logger,
		UpdateEnabled:     cfg.Update.Enabled,
		AllowDowngrade:    cfg.Update.AllowDowngrade,
		UpdateChannel:     cfg.Update.Channel,
		DownloadsDir:      "/var/lib/fpp-monitor-agent/downloads",
		BinaryPath:        "/opt/fpp-monitor-agent/fpp-monitor-agent",
		RebootEnabled:     cfg.RebootEnabled,
		RestartFPPCommand: cfg.RestartFPPCommand,
		AllowCIDRs:        cfg.NetworkAllowlist.CIDRs,
		AllowPorts:        cfg.NetworkAllowlist.Ports,
		CommandTimeout:    60 * time.Second,
	}

	heartbeatSender := &heartbeat.Sender{
		Client:       httpClient,
		Logger:       logger,
		APIBaseURL:   cfg.APIBaseURL,
		DeviceID:     cfg.DeviceID,
		DeviceToken:  cfg.DeviceToken,
		AgentVersion: version,
		FPPBaseURL:   cfg.FPPBaseURL,
		Interval:     time.Duration(cfg.HeartbeatIntervalSec) * time.Second,
		MaxBackoff:   60 * time.Second,
	}

	commandRunner := &commands.Runner{
		Client:       httpClient,
		Logger:       logger,
		APIBaseURL:   cfg.APIBaseURL,
		DeviceID:     cfg.DeviceID,
		DeviceToken:  cfg.DeviceToken,
		AgentVersion: version,
		Interval:     time.Duration(cfg.CommandPollIntervalSec) * time.Second,
		MaxBackoff:   60 * time.Second,
		Executor:     executor,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		heartbeatSender.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		commandRunner.Run(ctx)
	}()

	<-ctx.Done()
	logger.Info("shutdown", map[string]interface{}{"signal": "term"})
	wg.Wait()
}

func resolveConfigPath(flagValue string) (string, []string) {
	var checked []string
	if flagValue != "" {
		checked = append(checked, flagValue)
		if fileExists(flagValue) {
			return flagValue, checked
		}
		return "", checked
	}
	if envPath := os.Getenv("SHOWOPS_CONFIG_PATH"); envPath != "" {
		checked = append(checked, envPath)
		if fileExists(envPath) {
			return envPath, checked
		}
		return "", checked
	}
	defaults := []string{
		"/home/fpp/media/config/fpp-monitor-agent.json",
		"/etc/fpp-monitor-agent/config.json",
		"./config.json",
	}
	checked = append(checked, defaults...)
	for _, path := range defaults {
		if fileExists(path) {
			return path, checked
		}
	}
	return "", checked
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
