# FPP Monitor Agent

A small outbound-only management agent for FPP devices. It reports heartbeats, polls allowlisted commands, and executes them with timeouts. Standard library only.

## Install

1) Build (or use your own build pipeline):

```sh
VERSION=1.0.0 ./scripts/build.sh
```

Or:

```sh
make build
```

If scripts are not executable:

```sh
chmod +x scripts/*.sh install/*.sh
```

2) Copy the binary to the target and install:

```sh
sudo ./install/install.sh ./dist/fpp-monitor-agent-linux-armv7
```

3) Edit config (you can paste an `enrollment_token` and leave `device_token`/`device_id` empty for first boot):

```sh
sudo nano /home/fpp/media/config/fpp-monitor-agent.json
```

The install script will install and start the systemd service if `systemctl` exists.

## Run (manual)

```sh
/opt/fpp-monitor-agent/fpp-monitor-agent
```

Version:

```sh
/opt/fpp-monitor-agent/fpp-monitor-agent --version
```

## Configuration

Config file path (plugin default): `/home/fpp/media/config/fpp-monitor-agent.json`
Fallbacks: `/etc/fpp-monitor-agent/config.json`, `./config.json`
Overrides: `--config <path>` or `SHOWOPS_CONFIG_PATH`
Note: the config file must be writable by the `fpp` user so enrollment can persist `device_id` and `device_token`.

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
- `SHOWOPS_API_BASE_URL` (preferred override)
- `SHOWOPS_CONFIG_PATH`
- `SHOWOPS_DEBUG_HTTP=1`
- `SHOWOPS_DRY_RUN=1`

Enrollment:
- If `device_token` is empty and `enrollment_token` is set, the agent will enroll on startup, write `device_id`/`device_token`/`location_id` into the config file, and clear `enrollment_token`.
- After enrollment, restart the service if it does not restart automatically.
Token flow:
- `enrollment_token` is used only once for `POST /v1/agent/enroll`.
- The API returns `device_id` + `device_token`.
- The agent persists those to config and uses `Authorization: Bearer <device_token>` for heartbeat + command polling.

API endpoints:
- `POST /v1/agent/enroll` with `{ enrollment_token, hostname, label?, agent_version, fpp_version }`
- `POST /v1/ingest/heartbeat` with Authorization `Bearer <device_token>`
- `GET /v1/agent/commands/poll` returns `{ "commands": [] }`
- `POST /v1/agent/command-results` is not implemented on the Worker; the agent disables results if it gets `404`.

Enrollment response:
```json
{
  "device_id": "uuid",
  "device_token": "dtok_...",
  "location_id": "loc_...",
  "label": "Stage Left"
}
```

Local run:

```sh
./scripts/run_local.sh ./scripts/local-config.json
```

Debug/dry-run:

```sh
/opt/fpp-monitor-agent/fpp-monitor-agent --debug-http
/opt/fpp-monitor-agent/fpp-monitor-agent --dry-run
```

Platform detection:

```sh
./scripts/print_platform.sh
```

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

Verify on device:

```sh
sudo journalctl -u fpp-monitor-agent.service -n 200 --no-pager
```

Example curl (enroll):

```sh
curl -s -X POST https://api.showops.io/v1/agent/enroll \\
  -H "Content-Type: application/json" \\
  -d '{ "enrollment_token": "etok_...", "hostname": "fpp-main" }'
```

## Releases

- Tag a version `vX.Y.Z` and push the tag.
- GitHub Actions builds and attaches these exact release assets:
  - `fpp-monitor-agent-linux-armv7`
  - `fpp-monitor-agent-linux-arm64`
  - `checksums.txt`
- The plugin downloads the asset matching the platform and verifies `checksums.txt` contains lines in the form `sha256  <filename>` for the exact filenames above.
- To overwrite an existing tag (for example, `v0.1.3`), run the `release` workflow manually and set the tag input to the existing tag; assets are replaced in-place.
