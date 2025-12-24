# FPP Monitor Agent

A small outbound-only management agent for FPP devices. It reports heartbeats, polls allowlisted commands, and executes them with timeouts. Standard library only.

## Install

1) Build (or use your own build pipeline):

```sh
VERSION=1.0.0 ./scripts/build.sh
```

2) Copy the binary to the target and install:

```sh
sudo ./install/install.sh ./dist/fpp-monitor-agent-armv7
```

3) Edit config (you can paste an `enrollment_token` and leave `device_token`/`device_id` empty for first boot):

```sh
sudo nano /etc/fpp-monitor-agent/config.json
```

The install script will install and start the systemd service if `systemctl` exists.

## Run (manual)

```sh
/opt/fpp-monitor-agent/fpp-monitor-agent --config /etc/fpp-monitor-agent/config.json
```

## Configuration

Config file path: `/etc/fpp-monitor-agent/config.json`

```json
{
  "api_base_url": "https://api.showops.io",
  "enrollment_token": "",
  "device_token": "",
  "device_id": "",
  "location_id": "",
  "label": "",
  "heartbeat_interval_sec": 15,
  "command_poll_interval_sec": 7,
  "fpp_base_url": "http://127.0.0.1",
  "update": {
    "enabled": true,
    "channel": "stable",
    "allow_downgrade": false
  },
  "network_allowlist": {
    "cidrs": ["192.168.0.0/16"],
    "ports": [80, 443, 22]
  },
  "reboot_enabled": false,
  "restart_fpp_command": "systemctl restart fpp"
}
```

Environment overrides:
- `FPP_MONITOR_API_BASE_URL`
- `FPP_MONITOR_DEVICE_TOKEN`
- `FPP_MONITOR_DEVICE_ID`

Enrollment:
- If `device_token` is empty and `enrollment_token` is set, the agent will enroll on startup, write `device_id`/`device_token`/`location_id` into the config file, and clear `enrollment_token`.
- After enrollment, restart the service if it does not restart automatically.

## Systemd

Unit file: `systemd/fpp-monitor-agent.service`

```sh
sudo systemctl status fpp-monitor-agent.service
sudo journalctl -u fpp-monitor-agent.service
```

## Troubleshooting

- If the agent is not sending heartbeats, verify `api_base_url`, `device_token`, and outbound network access.
- If command execution fails, check journal logs for `command_result_send_failed` and ensure the command is allowlisted.
- For `network_probe`, ensure the host and port are inside the `network_allowlist` CIDRs/ports.

## Releases

- Tag a version `vX.Y.Z` and push the tag.
- GitHub Actions builds and attaches:
  - `dist/fpp-monitor-agent-linux-armv7`
  - `dist/fpp-monitor-agent-linux-arm64`
  - `dist/checksums.txt`
