package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"fpp-monitor-agent/internal/commands"
	"fpp-monitor-agent/internal/config"
	"fpp-monitor-agent/internal/enroll"
	"fpp-monitor-agent/internal/exec"
	"fpp-monitor-agent/internal/heartbeat"
	"fpp-monitor-agent/internal/httpclient"
	"fpp-monitor-agent/internal/log"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/fpp-monitor-agent/config.json", "config path")
	flag.Parse()

	logger := &log.Logger{}
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("config_load_failed", map[string]interface{}{"error": err.Error(), "path": *configPath})
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
		cfg.EnrollmentToken = ""
		if err := config.Save(*configPath, cfg); err != nil {
			logger.Error("config_write_failed", map[string]interface{}{"error": err.Error(), "path": *configPath})
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
