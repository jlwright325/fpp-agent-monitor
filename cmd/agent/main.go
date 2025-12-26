package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"fpp-agent-monitor/internal/commands"
	"fpp-agent-monitor/internal/config"
	"fpp-agent-monitor/internal/enroll"
	"fpp-agent-monitor/internal/exec"
	"fpp-agent-monitor/internal/fppcollector"
	"fpp-agent-monitor/internal/heartbeat"
	"fpp-agent-monitor/internal/httpclient"
	"fpp-agent-monitor/internal/log"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "config path")
	showVersion := flag.Bool("version", false, "print version")
	debugHTTP := flag.Bool("debug-http", false, "log HTTP URLs and auth scheme")
	dryRun := flag.Bool("dry-run", false, "log requests without sending")
	flag.Parse()

	if *showVersion {
		os.Stdout.WriteString(version + "\n")
		return
	}

	debugEnabled := *debugHTTP || envBool("SHOWOPS_DEBUG_HTTP")
	dryRunEnabled := *dryRun || envBool("SHOWOPS_DRY_RUN")
	logger := &log.Logger{Level: log.LevelError}
	if debugEnabled {
		logger.Level = log.LevelInfo
	}
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
	if cfg.DeviceToken == "" && cfg.EnrollmentToken == "" {
		logger.Error("enrollment_missing_token", map[string]interface{}{"path": resolvedPath})
		os.Exit(1)
	}

	httpClient := httpclient.New(10 * time.Second)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	retryBackoff := 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}

		if cfg.DeviceToken == "" && cfg.EnrollmentToken == "" {
			logger.Error("enrollment_missing_token", map[string]interface{}{"path": resolvedPath})
			os.Exit(1)
		}

		if cfg.DeviceToken == "" && cfg.EnrollmentToken != "" {
			if err := runEnrollment(ctx, logger, httpClient, cfg, resolvedPath, version, debugEnabled, dryRunEnabled); err != nil {
				var cwErr *configWriteError
				if errors.As(err, &cwErr) {
					logger.Error("config_write_failed", map[string]interface{}{
						"error": cwErr.Err.Error(),
						"path":  cwErr.Path,
					})
					if cwErr.Permission {
						logger.Error("config not writable; fix permissions on /home/fpp/media/config/fpp-monitor-agent.json", map[string]interface{}{
							"path": cwErr.Path,
						})
					}
					sleep(ctx, retryBackoff)
				} else {
					logger.Error("enrollment_failed", map[string]interface{}{"error": err.Error()})
					os.Exit(1)
				}
			}
		}
		if cfg.DeviceToken == "" {
			logger.Error("missing_device_token", map[string]interface{}{"path": resolvedPath})
			os.Exit(1)
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
			DebugHTTP:    debugEnabled,
			DryRun:       dryRunEnabled,
		}

		commandRunner := &commands.Runner{
			Client:                httpClient,
			Logger:                logger,
			APIBaseURL:            cfg.APIBaseURL,
			DeviceID:              cfg.DeviceID,
			DeviceToken:           cfg.DeviceToken,
			AgentVersion:          version,
			Interval:              time.Duration(cfg.CommandPollIntervalSec) * time.Second,
			MaxBackoff:            60 * time.Second,
			Executor:              executor,
			DebugHTTP:             debugEnabled,
			DryRun:                dryRunEnabled,
			CommandResultsEnabled: true,
		}

		runCtx, cancelRun := context.WithCancel(ctx)
		errCh := make(chan error, 3)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			errCh <- heartbeatSender.Run(runCtx)
		}()
		go func() {
			defer wg.Done()
			errCh <- commandRunner.Run(runCtx)
		}()

		var collector *fppcollector.Collector
		if cfg.FPPCollectEnabled != nil && *cfg.FPPCollectEnabled {
			collector = &fppcollector.Collector{
				Client:      httpClient,
				Logger:      logger,
				APIBaseURL:  cfg.APIBaseURL,
				DeviceID:    cfg.DeviceID,
				DeviceToken: cfg.DeviceToken,
				FPPBaseURL:  cfg.FPPBaseURL,
				Interval:    time.Duration(cfg.FPPCollectIntervalSec) * time.Second,
				MaxBackoff:  60 * time.Second,
				DebugHTTP:   debugEnabled,
				DryRun:      dryRunEnabled,
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				errCh <- collector.Run(runCtx)
			}()
		}

		var loopErr error
		select {
		case <-ctx.Done():
			cancelRun()
			wg.Wait()
			logger.Info("shutdown", map[string]interface{}{"signal": "term"})
			return
		case loopErr = <-errCh:
			cancelRun()
			wg.Wait()
		}

		if loopErr == nil {
			return
		}
		if errors.Is(loopErr, heartbeat.ErrUnauthorized) || errors.Is(loopErr, commands.ErrUnauthorized) {
			if cfg.EnrollmentToken != "" {
				logger.Warn("auth_unauthorized_reenroll", map[string]interface{}{"path": "/v1/agent/enroll"})
				if err := runEnrollment(ctx, logger, httpClient, cfg, resolvedPath, version, debugEnabled, dryRunEnabled); err != nil {
					logger.Error("enrollment_failed", map[string]interface{}{"error": err.Error()})
					return
				}
				retryBackoff = 5 * time.Second
				continue
			}
			sleep(ctx, retryBackoff)
			return
		}
		logger.Warn("agent_loop_error", map[string]interface{}{"error": loopErr.Error()})
		sleep(ctx, retryBackoff)
		retryBackoff = nextBackoff(retryBackoff)
	}
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

func runEnrollment(ctx context.Context, logger *log.Logger, client *httpclient.Client, cfg *config.Config, path, version string, debug, dryRun bool) error {
	logger.Info("enrollment_start", map[string]interface{}{"api_base_url": cfg.APIBaseURL})
	enroller := &enroll.Enroller{
		Client:       client,
		Logger:       logger,
		APIBaseURL:   cfg.APIBaseURL,
		AgentVersion: version,
		Token:        cfg.EnrollmentToken,
		Label:        cfg.Label,
		FPPBaseURL:   cfg.FPPBaseURL,
		MaxBackoff:   60 * time.Second,
		DebugHTTP:    debug,
		DryRun:       dryRun,
	}
	resp, err := enroller.Run(ctx)
	if err != nil {
		return err
	}
	cfg.DeviceID = strings.TrimSpace(resp.DeviceID)
	cfg.DeviceToken = strings.TrimSpace(resp.DeviceToken)
	cfg.LocationID = strings.TrimSpace(resp.LocationID)
	if resp.Label != "" {
		cfg.Label = strings.TrimSpace(resp.Label)
	}
	cfg.EnrollmentToken = ""
	if err := config.Save(path, cfg); err != nil {
		return &configWriteError{Path: path, Err: err, Permission: os.IsPermission(err)}
	}
	logger.Info("enrollment_success", map[string]interface{}{"device_id": cfg.DeviceID})
	return nil
}

func envBool(key string) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return val == "1" || val == "true" || val == "yes"
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return 5 * time.Second
	}
	next := current * 2
	if next > 60*time.Second {
		return 60 * time.Second
	}
	return next
}

type configWriteError struct {
	Path       string
	Err        error
	Permission bool
}

func (e *configWriteError) Error() string {
	return "config_write_failed: " + e.Err.Error()
}
