# mod_webhook_to_jid

Prosody module to receive Prometheus Alertmanager webhooks and deliver them as XMPP messages to Multi-User Chat (MUC) rooms or individual JIDs.

## Features

- Receives Alertmanager webhook notifications
- Delivers alerts to MUC rooms without joining (using internal API)
- Delivers alerts to individual JIDs as direct messages
- Formats alerts into human-readable XMPP messages
- **Custom message templates** with variable substitution
- **Debug logging** for payload inspection and troubleshooting
- Configurable emoji indicators for severity and status
- HTTP Basic Authentication for security
- Sends each alert as a separate message for real-time updates
- Supports both firing and resolved alerts

## Installation

1. Copy `mod_webhook_to_jid.lua` to your Prosody modules directory:
   ```bash
   cp mod_webhook_to_jid.lua /usr/local/lib/prosody-modules/mod_webhook_to_jid/
   ```

2. Enable the module in your Prosody configuration (see Configuration section below)

3. Reload Prosody:
   ```bash
   prosodyctl reload
   ```

## Configuration

### Prosody Configuration

Add the module to your VirtualHost configuration in `prosody.cfg.lua`:

```lua
VirtualHost "example.com"
    -- Enable required modules
    modules_enabled = {
	"http";              -- Required for HTTP endpoint
	"webhook_to_jid";    -- This module
	-- ... other modules ...
    }

    -- HTTP Basic Auth credentials for the webhook endpoint
    -- Alertmanager will use these to authenticate
    webhook_to_jid_username = "alertmanager"
    webhook_to_jid_password = "your-secret-password"

    -- The JID that will appear as the sender of alert messages
    -- This should be a valid JID on your server
    webhook_to_jid_from = "alerts@example.com"

    -- Nickname to display when sending to MUC rooms
    webhook_to_jid_muc_nickname = "Alertmanager"

    -- Enable or disable emoji indicators in messages
    webhook_to_jid_emoji = true

    -- (Optional) Customize severity emoji
    webhook_to_jid_severity_emoji = {
	critical = "🔴",
	warning = "🟠",
	info = "🔵",
	resolved = "🟢"
    }

    -- (Optional) Customize status emoji
    webhook_to_jid_status_emoji = {
	firing = "🔥",
	resolved = "✅"
    }
```

### Configuration Options Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `webhook_to_jid_username` | string | `"alertmanager"` | HTTP Basic Auth username |
| `webhook_to_jid_password` | string | `"changeme"` | HTTP Basic Auth password |
| `webhook_to_jid_from` | string | `"alerts@{host}"` | JID used as message sender |
| `webhook_to_jid_muc_nickname` | string | `"Alertmanager"` | Nickname shown in MUC rooms |
| `webhook_to_jid_emoji` | boolean | `true` | Enable/disable emoji indicators |
| `webhook_to_jid_severity_emoji` | table | See above | Emoji for severity levels |
| `webhook_to_jid_status_emoji` | table | See above | Emoji for alert status |
| `webhook_to_jid_use_template` | boolean | `false` | Use custom template instead of built-in formatting |
| `webhook_to_jid_template` | string | `nil` | Custom message template (multiline string) |
| `webhook_to_jid_debug` | boolean | `false` | Enable debug logging (logs to both Prosody log and separate file) |
| `webhook_to_jid_log_file` | string | `"/var/log/prosody/webhook_to_jid.log"` | Path to separate debug log file |

## Alertmanager Configuration

Configure Alertmanager to send webhooks to the module endpoint.

### Basic Configuration

Add a receiver to your `alertmanager.yml`:

```yaml
receivers:
  - name: 'xmpp-alerts'
    webhook_configs:
      - url: 'https://example.com:5281/webhook_to_jid/alerts@conference.example.com'
	send_resolved: true
	http_config:
	  basic_auth:
	    username: 'alertmanager'
	    password: 'your-secret-password'
	  tls_config:
	    insecure_skip_verify: false
```

### Multiple Receivers

You can configure multiple receivers for different alert types or severity levels:

```yaml
receivers:
  # Send critical alerts to an ops MUC room
  - name: 'xmpp-critical'
    webhook_configs:
      - url: 'https://example.com:5281/webhook_to_jid/ops@conference.example.com'
	send_resolved: true
	http_config:
	  basic_auth:
	    username: 'alertmanager'
	    password: 'your-secret-password'

  # Send warnings to a monitoring MUC room
  - name: 'xmpp-warnings'
    webhook_configs:
      - url: 'https://example.com:5281/webhook_to_jid/monitoring@conference.example.com'
	send_resolved: true
	http_config:
	  basic_auth:
	    username: 'alertmanager'
	    password: 'your-secret-password'

  # Send alerts to individual admin
  - name: 'xmpp-admin'
    webhook_configs:
      - url: 'https://example.com:5281/webhook_to_jid/admin@example.com'
	send_resolved: true
	http_config:
	  basic_auth:
	    username: 'alertmanager'
	    password: 'your-secret-password'

route:
  # Default receiver
  receiver: 'xmpp-warnings'

  # Route critical alerts to ops room
  routes:
    - match:
	severity: critical
      receiver: 'xmpp-critical'

    # Route specific service alerts to admin
    - match:
	service: database
      receiver: 'xmpp-admin'
```

### URL Format

The webhook URL format is:
```
https://{prosody-server}:{port}/webhook_to_jid/{target-jid}
```

Where:
- `{prosody-server}` - Your Prosody server hostname
- `{port}` - Prosody HTTPS port (default: 5281)
- `{target-jid}` - The destination JID (MUC room or user)

**Examples:**
- MUC room: `https://xmpp.example.com:5281/webhook_to_jid/alerts@conference.example.com`
- Individual user: `https://xmpp.example.com:5281/webhook_to_jid/admin@example.com`

## Message Format

Alerts are formatted into readable multi-line messages. You can use either the built-in formatting or create custom templates.

### Built-in Formatting (Default)

When `webhook_to_jid_use_template = false` or not set, the module uses built-in formatting.

### Example Message (with emoji enabled)

```
🔥 🔴 FIRING: HighCPUUsage

Summary: CPU usage is critically high
Description: Server CPU usage has exceeded 90% for more than 5 minutes

Labels:
  • instance: server01.example.com
  • job: node_exporter
  • region: us-east-1

Started: 2025-11-14 20:30:17 UTC

Details: https://prometheus.example.com/graph?g0.expr=...
```

### Example Message (emoji disabled)

```
[FIRING] [CRITICAL] HighCPUUsage

Summary: CPU usage is critically high
Description: Server CPU usage has exceeded 90% for more than 5 minutes

Labels:
  • instance: server01.example.com
  • job: node_exporter
  • region: us-east-1

Started: 2025-11-14 20:30:17 UTC

Details: https://prometheus.example.com/graph?g0.expr=...
```

### Resolved Alert Example

```
✅ 🟢 RESOLVED: HighCPUUsage

Summary: CPU usage has returned to normal
Description: Server CPU usage is now below threshold

Labels:
  • instance: server01.example.com
  • job: node_exporter
  • region: us-east-1

Started: 2025-11-14 20:30:17 UTC
Ended: 2025-11-14 20:45:32 UTC

Details: https://prometheus.example.com/graph?g0.expr=...
```

### Custom Templates

You can create custom message templates to show only the fields you need.

#### Enabling Templates

```lua
webhook_to_jid_use_template = true
webhook_to_jid_template = [[
{status_emoji} {severity_emoji} {status}: {alertname}

{annotations.summary}

Host: {labels.instance}
Service: {labels.job}
Environment: {labels.env}

Started: {startsAt}
{endsAt}

{generatorURL}
]]
```

#### Available Template Variables

**Basic Variables:**
- `{status}` - Alert status: "FIRING" or "RESOLVED"
- `{alertname}` - Name of the alert
- `{severity}` - Severity level: "CRITICAL", "WARNING", "INFO"
- `{status_emoji}` - Emoji for status (🔥 or ✅) if emoji enabled
- `{severity_emoji}` - Emoji for severity (🔴, 🟠, 🔵) if emoji enabled

**Label Access (dot notation):**
- `{labels.KEY}` - Access any label by key
  - Example: `{labels.instance}`, `{labels.job}`, `{labels.region}`
  - Returns empty string if label doesn't exist

**Annotation Access (dot notation):**
- `{annotations.KEY}` - Access any annotation by key
  - Example: `{annotations.summary}`, `{annotations.description}`
  - Returns empty string if annotation doesn't exist

**Timestamps:**
- `{startsAt}` - Formatted start time (e.g., "2025-11-14 20:30:00 UTC")
- `{endsAt}` - Formatted end time (only for resolved alerts, includes "Ended:" prefix)
- `{startsAt_raw}` - Raw ISO 8601 timestamp
- `{endsAt_raw}` - Raw ISO 8601 timestamp

**URLs:**
- `{generatorURL}` - Link to Prometheus (includes "Details:" prefix if present)

**Auto-formatted Collections:**
- `{all_labels}` - All labels formatted as bullet list (excludes alertname and severity)
- `{all_annotations}` - All annotations formatted with capitalized keys

#### Template Behavior

1. **Missing values** - Variables that don't exist become empty strings
2. **Empty lines removed** - Lines containing only whitespace after substitution are removed
3. **Conditional display** - Use variables like `{endsAt}` that are only populated for resolved alerts
4. **No loops needed** - Use `{all_labels}` or `{all_annotations}` for automatic formatting

#### Template Example: Minimal

```lua
webhook_to_jid_template = [[
{status_emoji} {alertname} on {labels.instance}
{annotations.summary}
{generatorURL}
]]
```

Output:
```
🔥 HighCPU on server01.example.com
CPU usage is critically high
Details: https://prometheus.example.com/graph?g0.expr=...
```

#### Template Example: Detailed with Custom Labels

```lua
webhook_to_jid_template = [[
{status_emoji} {severity_emoji} [{severity}] {alertname}

Summary: {annotations.summary}
Description: {annotations.description}

Infrastructure:
  Instance: {labels.instance}
  Job: {labels.job}
  Environment: {labels.env}
  Region: {labels.region}

Timeline:
  Started: {startsAt}
  {endsAt}

{generatorURL}
]]
```

#### Template Example: Slack-style

```lua
webhook_to_jid_template = [[
*{status}*: {alertname} | Severity: {severity}
{annotations.summary}

*Instance:* `{labels.instance}`
*Started:* {startsAt}

<{generatorURL}|View in Prometheus>
]]
```

## Debug Mode

Enable debug logging to see raw webhook payloads and formatted messages in Prosody logs.

### Enabling Debug Mode

```lua
webhook_to_jid_debug = true
```

### What Gets Logged

**Normal mode** (`webhook_to_jid_debug = false`):
```
webhook_to_jid: Received webhook for target: alerts@conference.example.com
webhook_to_jid: Processing 3 alert(s) for target alerts@conference.example.com
webhook_to_jid: Sent alert to MUC: alerts@conference.example.com
webhook_to_jid: Webhook processing complete: 3 succeeded, 0 failed
```

**Debug mode** (`webhook_to_jid_debug = true`):
```
webhook_to_jid: ========== WEBHOOK RECEIVED ==========
webhook_to_jid: Source IP: 10.0.1.5
webhook_to_jid: Request path: /webhook_to_jid/alerts@conference.example.com
webhook_to_jid: Target JID: alerts@conference.example.com
webhook_to_jid: Target type: MUC
webhook_to_jid: Raw JSON payload:
{
  "receiver": "xmpp-alerts",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {
	"alertname": "HighCPU",
	"severity": "critical",
	"instance": "server01",
	"job": "node_exporter"
      },
      "annotations": {
	"summary": "CPU usage high",
	"description": "CPU > 90%"
      },
      "startsAt": "2025-11-14T20:30:00Z"
    }
  ]
}
webhook_to_jid: Processing alert 1/1: HighCPU
webhook_to_jid: Alert details: status=firing, severity=critical
webhook_to_jid: ========== FORMATTED MESSAGE ==========
🔥 🔴 FIRING: HighCPU

Summary: CPU usage high
Description: CPU > 90%

Labels:
  • instance: server01
  • job: node_exporter

Started: 2025-11-14 20:30:00 UTC

Details: http://prometheus:9090/...
webhook_to_jid: ========== END MESSAGE ==========
webhook_to_jid: Broadcasting message to MUC alerts@conference.example.com using internal API
webhook_to_jid: Sent alert to MUC: alerts@conference.example.com
webhook_to_jid: Delivery result: success
webhook_to_jid: Webhook processing complete: 1 succeeded, 0 failed
webhook_to_jid: ========== WEBHOOK COMPLETE ==========
```

### Viewing Debug Logs

```bash
# Follow logs in real-time
tail -f /var/log/prosody/prosody.log | grep webhook_to_jid

# Extract raw payloads
grep "Raw JSON payload:" -A 50 /var/log/prosody/prosody.log

# Extract formatted messages
grep "FORMATTED MESSAGE" -A 20 /var/log/prosody/prosody.log

# See only webhook processing
grep "WEBHOOK RECEIVED\|WEBHOOK COMPLETE" /var/log/prosody/prosody.log
```

### Use Cases for Debug Mode

1. **Template Development** - See exactly how your template renders with real alert data
2. **Field Discovery** - Find what labels and annotations are available in your alerts
3. **Troubleshooting** - Diagnose why messages aren't formatted as expected
4. **Integration Testing** - Verify Alertmanager is sending the correct payload format

**Note:** Debug mode logs can be verbose. Enable only when needed for troubleshooting or development.

## Testing

### Manual Testing with curl

Test the webhook endpoint manually:

```bash
curl -k -X POST \
  -u "alertmanager:your-secret-password" \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [
      {
	"status": "firing",
	"labels": {
	  "alertname": "TestAlert",
	  "severity": "warning",
	  "instance": "test-server"
	},
	"annotations": {
	  "summary": "This is a test alert",
	  "description": "Testing the webhook integration"
	},
	"startsAt": "2025-11-14T20:00:00Z",
	"generatorURL": "http://prometheus:9090/graph"
      }
    ]
  }' \
  https://example.com:5281/webhook_to_jid/alerts@conference.example.com
```

Expected response (success):
```json
{
  "status": "success",
  "message": "Successfully delivered 1 alert(s) to alerts@conference.example.com"
}
```

### Checking Logs

Monitor Prosody logs for webhook activity:

```bash
# Follow the log in real-time
tail -f /var/log/prosody/prosody.log | grep webhook_to_jid

# Check for errors
grep -i "webhook_to_jid.*error" /var/log/prosody/prosody.log

# View recent webhook requests
grep "webhook_to_jid" /var/log/prosody/prosody.log | tail -20
```

## Troubleshooting

### No messages appearing in MUC

**Problem:** Webhook returns success but no messages appear in the MUC room.

**Solutions:**
1. Verify the MUC room exists and is accessible
2. Check that the MUC component is loaded: `prosodyctl about | grep muc`
3. Review MUC component logs: `grep "conference.example.com" /var/log/prosody/prosody.log`
4. Ensure the module is loaded on the correct VirtualHost

### HTTP 401 Unauthorized

**Problem:** Alertmanager receives 401 errors.

**Solutions:**
1. Verify username/password match in both configurations
2. Check that Basic Auth is properly configured in alertmanager.yml
3. Review webhook logs: `grep "Unauthorized webhook" /var/log/prosody/prosody.log`

### HTTP 404 Not Found

**Problem:** Webhook endpoint not found.

**Solutions:**
1. Verify module is loaded: `prosodyctl about | grep webhook_to_jid`
2. Check HTTP module is enabled in prosody.cfg.lua
3. Verify URL format: `/webhook_to_jid/{jid}`
4. Ensure Prosody is listening on the correct port (default 5281 for HTTPS)

### Module fails to load

**Problem:** Error during Prosody startup or reload.

**Solutions:**
1. Check Prosody version compatibility (tested with 0.13+)
2. Verify module file location and permissions
3. Review startup logs: `grep "webhook_to_jid" /var/log/prosody/prosody.log`
4. Check for syntax errors in prosody.cfg.lua

### Messages not formatted correctly

**Problem:** Alert messages appear with broken formatting or missing fields.

**Solutions:**
1. Enable debug mode to see the raw payload and formatted output
2. Verify emoji support in your XMPP client
3. Try disabling emoji: `webhook_to_jid_emoji = false`
4. Check that Alertmanager is sending v4 webhook format
5. If using templates, verify variable names match your alert labels/annotations

### Template not working

**Problem:** Custom template doesn't render correctly or shows `{variables}` literally.

**Solutions:**
1. Ensure `webhook_to_jid_use_template = true` is set
2. Verify template syntax uses `{variable}` not `${variable}` or `%{variable}`
3. Enable debug mode to see what the template produces
4. Check variable names match your alert structure (use debug logs to see available fields)
5. For nested fields, use dot notation: `{labels.instance}` not `{labels[instance]}`

## Security Considerations

1. **Use HTTPS:** Always use HTTPS (port 5281) for webhook endpoints in production
2. **Strong Passwords:** Use strong, random passwords for HTTP Basic Auth
3. **Network Security:** Consider firewall rules to restrict webhook access to Alertmanager servers only
4. **TLS Verification:** Enable TLS certificate verification in Alertmanager (don't use `insecure_skip_verify: true` in production)
5. **Credential Rotation:** Regularly rotate webhook credentials

## Performance Notes

- Each alert in the webhook payload is sent as a separate XMPP message
- For MUC delivery, the module uses internal MUC API for efficient message broadcast
- No persistent connections are maintained; the module is stateless
- HTTP requests are processed synchronously but XMPP message delivery is asynchronous

## Compatibility

- **Prosody:** 0.13.x or newer
- **Alertmanager:** v0.20.0+ (webhook v4 format)
- **XMPP Clients:** Any client supporting MUC (XEP-0045) or basic messaging
