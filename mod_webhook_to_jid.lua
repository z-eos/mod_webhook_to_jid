-- mod_webhook_to_jid.lua
-- Prosody module to receive Alertmanager webhooks and deliver them to XMPP JIDs or MUCs
--
-- Description:
--   This module provides an HTTP endpoint that receives webhook notifications from
--   Prometheus Alertmanager and delivers them as XMPP messages. It supports both:
--   - Multi-User Chat (MUC) rooms - messages are broadcast to all participants
--   - Individual JIDs - messages are sent as direct chat messages
--
-- Author: Generated for alerting integration
-- License: MIT
-- Version: 1.1.0

local MODULE_VERSION = "1.1.0";
--
-- Configuration Example:
--   VirtualHost "example.com"
--       modules_enabled = { "http"; "webhook_to_jid" }
--       
--       -- HTTP Basic Auth credentials for webhook endpoint
--       webhook_to_jid_username = "alertmanager"
--       webhook_to_jid_password = "secret-password"
--       
--       -- The JID that will appear as sender
--       webhook_to_jid_from = "alerts@example.com"
--       
--       -- Nickname to use when appearing in MUC rooms
--       webhook_to_jid_muc_nickname = "Alertmanager"
--       
--       -- Enable/disable emoji indicators in messages
--       webhook_to_jid_emoji = true
--       
--       -- Enable debug logging (logs raw payloads and formatted messages)
--       webhook_to_jid_debug = false
--       
--       -- Use custom template instead of default formatting
--       webhook_to_jid_use_template = false
--       
--       -- Custom message template (if use_template = true)
--       webhook_to_jid_template = [[
--{status_emoji} {severity_emoji} {status}: {alertname}
--
--{annotations.summary}
--
--Host: {labels.instance}
--Service: {labels.job}
--
--Started: {startsAt}
--{endsAt}
--
--Details: {generatorURL}
--]]
--       
--       -- Customize emoji for different severity levels (optional)
--       webhook_to_jid_severity_emoji = {
--           critical = "🔴",
--           warning = "🟠",
--           info = "🔵",
--           resolved = "🟢"
--       }
--       
--       -- Customize emoji for alert status (optional)
--       webhook_to_jid_status_emoji = {
--           firing = "🔥",
--           resolved = "✅"
--       }

local http = require "net.http";
local json = require "util.json";
local jid_split = require "util.jid".split;
local jid_bare = require "util.jid".bare;
local jid_join = require "util.jid".join;
local st = require "util.stanza";
local datetime = require "util.datetime";
local base64 = require "util.encodings".base64;

-- ============================================================================
-- CONFIGURATION
-- ============================================================================

-- HTTP Basic Authentication credentials for the webhook endpoint
local auth_username = module:get_option_string("webhook_to_jid_username", "alertmanager");
local auth_password = module:get_option_string("webhook_to_jid_password", "changeme");

-- The JID that will appear as the sender of messages
local default_from = module:get_option_string("webhook_to_jid_from", "alerts@" .. module.host);

-- Nickname to use when sending to MUC rooms
local muc_nickname = module:get_option_string("webhook_to_jid_muc_nickname", "Alertmanager");

-- Whether to include emoji indicators in formatted messages
local use_emoji = module:get_option_boolean("webhook_to_jid_emoji", true);

-- Enable debug logging (logs payloads and formatted messages)
local debug_mode = module:get_option_boolean("webhook_to_jid_debug", false);

-- Log file path for detailed webhook logging (only used when debug_mode = true)
local log_file_path = module:get_option_string("webhook_to_jid_log_file", "/var/log/prosody/webhook_to_jid.log");

-- Use custom template instead of built-in formatting
local use_template = module:get_option_boolean("webhook_to_jid_use_template", false);

-- Custom message template
local message_template = module:get_option_string("webhook_to_jid_template", nil);

-- Emoji mappings for different alert severity levels
-- These can be customized via configuration
local severity_emoji = module:get_option("webhook_to_jid_severity_emoji", {
    critical = "🔴",
    warning = "🟠",
    info = "🔵",
    resolved = "🟢",
});

-- Emoji mappings for alert firing/resolved status
-- These can be customized via configuration
local status_emoji = module:get_option("webhook_to_jid_status_emoji", {
    firing = "🔥",
    resolved = "✅",
});

-- ============================================================================
-- AUTHENTICATION
-- ============================================================================

--- Validates HTTP Basic Authentication credentials
-- @param request The HTTP request object
-- @return boolean True if authentication is valid, false otherwise
local function check_auth(request)
    local auth_header = request.headers.authorization;
    if not auth_header then
        return false;
    end
    
    -- Parse "Basic <base64>" format
    local auth_type, auth_data = auth_header:match("^(%S+)%s+(.+)$");
    if auth_type ~= "Basic" then
        return false;
    end
    
    -- Decode base64 credentials
    local decoded = base64.decode(auth_data);
    if not decoded then
        return false;
    end
    
    -- Extract username and password
    local username, password = decoded:match("^([^:]+):(.*)$");
    return username == auth_username and password == auth_password;
end

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

--- Formats an ISO 8601 timestamp into a human-readable format
-- @param iso_timestamp String in ISO 8601 format
-- @return Formatted datetime string or original if parsing fails
local function format_timestamp(iso_timestamp)
    if not iso_timestamp then
        return "N/A";
    end
    
    local parsed = datetime.parse(iso_timestamp);
    if parsed then
        return datetime.datetime(parsed);
    end
    return iso_timestamp;
end

--- Safely get a nested value from a table using dot notation
-- Example: get_nested_value({labels = {instance = "server1"}}, "labels.instance") -> "server1"
-- @param tbl The table to search in
-- @param path Dot-separated path (e.g., "labels.instance")
-- @return The value at the path, or nil if not found
local function get_nested_value(tbl, path)
    local keys = {};
    for key in path:gmatch("[^.]+") do
        table.insert(keys, key);
    end
    
    local value = tbl;
    for _, key in ipairs(keys) do
        if type(value) ~= "table" then
            return nil;
        end
        value = value[key];
        if value == nil then
            return nil;
        end
    end
    
    return value;
end

--- Pretty-prints a Lua table as JSON with indentation
-- @param tbl The table to encode
-- @return JSON string with formatting
local function pretty_json(tbl)
    -- Prosody's json.encode doesn't support pretty printing by default
    -- So we'll just use standard encoding and add basic formatting
    local encoded = json.encode(tbl);
    if not encoded then
        return "Error encoding JSON";
    end
    
    -- Basic pretty printing: add newlines after commas and braces
    encoded = encoded:gsub(",", ",\n  ");
    encoded = encoded:gsub("{", "{\n  ");
    encoded = encoded:gsub("}", "\n}");
    encoded = encoded:gsub("%[", "[\n  ");
    encoded = encoded:gsub("%]", "\n]");
    
    return encoded;
end

-- ============================================================================
-- MESSAGE FORMATTING
-- ============================================================================

--- Formats a single alert using a custom template
-- Replaces variables in the template with actual alert data
-- Supports nested field access like {labels.instance}
-- Removes lines that are empty after substitution
--
-- @param alert Table containing alert data from Alertmanager
-- @param template String template with {variable} placeholders
-- @return String containing formatted message body
local function format_alert_with_template(alert, template)
    local status = alert.status or "unknown";
    local alertname = alert.labels and alert.labels.alertname or "Unknown Alert";
    local severity = alert.labels and alert.labels.severity or "info";
    
    -- Build a table of all available variables
    local vars = {
        -- Basic fields
        status = status:upper(),
        alertname = alertname,
        severity = severity:upper(),
        
        -- Emoji (empty if disabled)
        status_emoji = use_emoji and (status_emoji[status] or "⚠️") or "",
        severity_emoji = use_emoji and (severity_emoji[severity] or "⚪") or "",
        
        -- Timestamps
        startsAt = alert.startsAt and format_timestamp(alert.startsAt) or "",
        endsAt = (alert.endsAt and status == "resolved") and format_timestamp(alert.endsAt) or "",
        startsAt_raw = alert.startsAt or "",
        endsAt_raw = alert.endsAt or "",
        
        -- URL
        generatorURL = alert.generatorURL or "",
        
        -- Store references to nested tables for dot notation access
        labels = alert.labels or {},
        annotations = alert.annotations or {},
    };
    
    -- Format all_labels and all_annotations if needed
    local all_labels = {};
    if alert.labels then
        for key, value in pairs(alert.labels) do
            if key ~= "alertname" and key ~= "severity" then
                table.insert(all_labels, string.format("  • %s: %s", key, value));
            end
        end
    end
    vars.all_labels = table.concat(all_labels, "\n");
    
    local all_annotations = {};
    if alert.annotations then
        for key, value in pairs(alert.annotations) do
            if value and value ~= "" then
                table.insert(all_annotations, string.format("%s: %s", key:gsub("^%l", string.upper), value));
            end
        end
    end
    vars.all_annotations = table.concat(all_annotations, "\n");
    
    -- Replace variables in template
    local result = template;
    
    -- First pass: replace direct variables like {status}, {alertname}
    result = result:gsub("{([%w_]+)}", function(var)
        return vars[var] or "";
    end);
    
    -- Second pass: replace nested variables like {labels.instance}
    result = result:gsub("{([%w_]+)%.([%w_]+)}", function(table_name, key)
        if vars[table_name] and type(vars[table_name]) == "table" then
            return vars[table_name][key] or "";
        end
        return "";
    end);
    
    -- Remove lines that are empty or contain only whitespace after substitution
    local lines = {};
    for line in result:gmatch("[^\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$");
        if trimmed ~= "" then
            table.insert(lines, line);
        end
    end
    
    return table.concat(lines, "\n");
end

--- Formats a single alert into a readable message using built-in formatting
-- Creates a multi-line message with alert details including:
-- - Status and severity indicators (with optional emoji)
-- - Annotations (summary, description, etc.)
-- - Labels (excluding alertname and severity which are in header)
-- - Timestamps (start time, and end time for resolved alerts)
-- - Generator URL if available
--
-- @param alert Table containing alert data from Alertmanager
-- @return String containing formatted message body
local function format_alert_builtin(alert)
    local lines = {};
    local status = alert.status or "unknown";
    local alertname = alert.labels and alert.labels.alertname or "Unknown Alert";
    local severity = alert.labels and alert.labels.severity or "info";
    
    -- Build the header line with status and alert name
    local header = "";
    if use_emoji then
        local status_icon = status_emoji[status] or "⚠️";
        local severity_icon = severity_emoji[severity] or "⚪";
        header = string.format("%s %s %s: %s", status_icon, severity_icon, status:upper(), alertname);
    else
        header = string.format("[%s] [%s] %s", status:upper(), severity:upper(), alertname);
    end
    table.insert(lines, header);
    table.insert(lines, "");
    
    -- Add annotations section (summary, description, runbook_url, etc.)
    if alert.annotations then
        for key, value in pairs(alert.annotations) do
            if value and value ~= "" then
                -- Capitalize first letter of annotation name
                table.insert(lines, string.format("%s: %s", key:gsub("^%l", string.upper), value));
            end
        end
        if next(alert.annotations) then
            table.insert(lines, "");
        end
    end
    
    -- Add labels section (excluding alertname and severity as they're in header)
    if alert.labels then
        table.insert(lines, "Labels:");
        for key, value in pairs(alert.labels) do
            if key ~= "alertname" and key ~= "severity" then
                table.insert(lines, string.format("  • %s: %s", key, value));
            end
        end
        table.insert(lines, "");
    end
    
    -- Add timestamp information
    if alert.startsAt then
        table.insert(lines, string.format("Started: %s", format_timestamp(alert.startsAt)));
    end
    if alert.endsAt and status == "resolved" then
        table.insert(lines, string.format("Ended: %s", format_timestamp(alert.endsAt)));
    end
    
    -- Add generator URL if available (link to Prometheus expression)
    if alert.generatorURL then
        table.insert(lines, "");
        table.insert(lines, string.format("Details: %s", alert.generatorURL));
    end
    
    return table.concat(lines, "\n");
end

--- Main alert formatting function that chooses between template and built-in formatting
-- @param alert Table containing alert data from Alertmanager
-- @return String containing formatted message body
local function format_alert(alert)
    if use_template and message_template then
        return format_alert_with_template(alert, message_template);
    else
        return format_alert_builtin(alert);
    end
end

-- ============================================================================
-- MESSAGE DELIVERY
-- ============================================================================

--- Sends a message to a Multi-User Chat (MUC) room
-- Uses the MUC internal API to broadcast messages directly without joining.
-- This requires access to the MUC host's module API.
--
-- @param muc_jid The bare JID of the MUC room (e.g., "alerts@conference.example.com")
-- @param from_jid The JID to use as the sender (currently unused, kept for API consistency)
-- @param message_body The text content to send
-- @return boolean True if message was sent successfully, false on error
local function send_to_muc(muc_jid, from_jid, message_body)
    local node, host = jid_split(muc_jid);
    
    -- Validate the MUC JID format
    if not node or not host then
        module:log("error", "Invalid MUC JID: %s", muc_jid);
        return false;
    end
    
    -- Get the Prosody host object for the MUC service
    local muc_host = prosody.hosts[host];
    if not muc_host then
        module:log("error", "MUC host not found: %s", host);
        return false;
    end
    
    -- Get the MUC module's get_room_from_jid function
    local get_room_from_jid = muc_host.modules.muc and muc_host.modules.muc.get_room_from_jid;
    if not get_room_from_jid then
        module:log("error", "MUC module not loaded on host: %s", host);
        return false;
    end
    
    -- Get the room object
    local room = get_room_from_jid(muc_jid);
    if not room then
        module:log("error", "MUC room not found: %s", muc_jid);
        return false;
    end
    
    -- Create a message stanza with the configured nickname
    -- The "from" JID includes the room JID with nickname as resource
    local from_jid_with_nick = jid_join(node, host, muc_nickname);
    local message_stanza = st.message({
        from = from_jid_with_nick,
        to = muc_jid,
        type = "groupchat"
    }):tag("body"):text(message_body):up();
    
    if debug_mode then
        module:log("debug", "Broadcasting message to MUC %s using internal API", muc_jid);
    end
    
    -- Use the room's broadcast_message function to send directly to all occupants
    -- This bypasses the need to join/leave the room
    room:broadcast_message(message_stanza);
    
    module:log("info", "Sent alert to MUC: %s", muc_jid);
    return true;
end

--- Sends a message to an individual JID as a direct chat message
-- @param target_jid The JID to send to (e.g., "user@example.com")
-- @param from_jid The JID to use as the sender
-- @param message_body The text content to send
-- @return boolean Always returns true (message queued for delivery)
local function send_to_jid(target_jid, from_jid, message_body)
    local bare_jid = jid_bare(target_jid);
    
    -- Create a chat message stanza
    local stanza = st.message({
        from = from_jid,
        to = bare_jid,
        type = "chat"
    }):tag("body"):text(message_body):up();
    
    if debug_mode then
        module:log("debug", "Sending message to JID %s from %s", bare_jid, from_jid);
    end
    
    -- Send the message (queued for delivery by Prosody's routing system)
    module:send(stanza);
    
    module:log("info", "Sent alert to JID: %s", bare_jid);
    return true;
end

--- Determines if a JID represents a MUC room or a regular user
-- Uses heuristics based on common MUC host naming patterns.
--
-- @param target_jid The JID to check
-- @return boolean True if likely a MUC, false otherwise
local function is_muc(target_jid)
    local node, host = jid_split(target_jid);
    
    -- Check for common MUC service subdomain patterns
    if host and (host:match("^conference%.") or host:match("^muc%.") or host:match("^chat%.")) then
        return true;
    end
    
    -- Additional detection logic can be added here if needed
    -- For example: checking if the host is registered as a MUC component
    return false;
end

-- ============================================================================
-- WEBHOOK HANDLER
-- ============================================================================

--- Main HTTP webhook request handler
-- Processes incoming POST requests from Alertmanager and delivers formatted
-- alerts to the specified target JID.
--
-- Expected URL format: POST /webhook_to_jid/{target_jid}
-- Expected body: JSON payload from Alertmanager (v4 format)
--
-- @param event HTTP request event from Prosody
-- @return HTTP response (string or status code)
local function handle_webhook(event)
    local request = event.request;
    local response = event.response;
    
    if debug_mode then
        module:log("debug", "========== WEBHOOK RECEIVED ==========");
    end
    
    -- Verify HTTP Basic Authentication
    if not check_auth(request) then
        module:log("warn", "Unauthorized webhook request from %s", request.ip or "unknown");
        response.status_code = 401;
        response.headers.www_authenticate = 'Basic realm="Alertmanager Webhook"';
        return "Unauthorized";
    end
    
    -- Extract the target JID from the URL path
    local path = request.path or "";
    
    if debug_mode then
        module:log("debug", "Source IP: %s", request.ip or "unknown");
        module:log("debug", "Request path: %s", path);
    end
    
    -- Try to match both full path and stripped path
    -- (Prosody may or may not include the module base path)
    local target_jid = path:match("^/webhook_to_jid/(.+)$") or path:match("^/(.+)$");
    
    if not target_jid or target_jid == "" then
        module:log("warn", "No target JID in webhook URL: %s", path);
        response.status_code = 400;
        return json.encode({error = "Target JID must be specified in URL path: /webhook_to_jid/{jid}"});
    end
    
    -- URL decode the JID (in case of special characters)
    target_jid = http.urldecode(target_jid);
    
    if debug_mode then
        module:log("debug", "Target JID: %s", target_jid);
    end
    
    module:log("info", "Received webhook for target: %s", target_jid);
    
    -- Parse the JSON payload
    local body = request.body;
    if not body or body == "" then
        module:log("warn", "Empty webhook body");
        response.status_code = 400;
        return json.encode({error = "Empty request body"});
    end
    
    local data, err = json.decode(body);
    if not data then
        module:log("error", "Failed to parse JSON: %s", err or "unknown error");
        response.status_code = 400;
        return json.encode({error = "Invalid JSON: " .. (err or "unknown error")});
    end
    
    -- Log raw payload in debug mode
    if debug_mode then
        module:log("debug", "Raw JSON payload:");
        module:log("debug", pretty_json(data));
    end
    
    -- Validate that we have alerts in the payload
    local alerts = data.alerts;
    if not alerts or type(alerts) ~= "table" or #alerts == 0 then
        module:log("warn", "No alerts in webhook payload");
        response.status_code = 400;
        return json.encode({error = "No alerts found in payload"});
    end
    
    module:log("info", "Processing %d alert(s) for target %s", #alerts, target_jid);
    
    -- Determine delivery method based on target type
    local from_jid = default_from;
    local success_count = 0;
    local fail_count = 0;
    local target_is_muc = is_muc(target_jid);
    
    if debug_mode then
        module:log("debug", "Target type: %s", target_is_muc and "MUC" or "JID");
    end
    
    -- Process each alert individually and send as separate messages
    -- This allows users to see alert updates in real-time rather than batched
    for i, alert in ipairs(alerts) do
        local alertname = alert.labels and alert.labels.alertname or "Unknown";
        local status = alert.status or "unknown";
        local severity = alert.labels and alert.labels.severity or "unknown";
        
        if debug_mode then
            module:log("debug", "Processing alert %d/%d: %s", i, #alerts, alertname);
            module:log("debug", "Alert details: status=%s, severity=%s", status, severity);
        end
        
        local message_body = format_alert(alert);
        
        if debug_mode then
            module:log("debug", "========== FORMATTED MESSAGE ==========");
            module:log("debug", message_body);
            module:log("debug", "========== END MESSAGE ==========");
        end
        
        local success;
        
        if target_is_muc then
            success = send_to_muc(target_jid, from_jid, message_body);
        else
            success = send_to_jid(target_jid, from_jid, message_body);
        end
        
        if success then
            success_count = success_count + 1;
            if debug_mode then
                module:log("debug", "Delivery result: success");
            end
        else
            fail_count = fail_count + 1;
            if debug_mode then
                module:log("debug", "Delivery result: failed");
            end
        end
    end
    
    module:log("info", "Webhook processing complete: %d succeeded, %d failed", success_count, fail_count);
    
    if debug_mode then
        module:log("debug", "========== WEBHOOK COMPLETE ==========");
    end
    
    -- Return appropriate HTTP response based on delivery results
    response.headers.content_type = "application/json";
    
    if fail_count == 0 then
        response.status_code = 200;
        return json.encode({
            status = "success",
            message = string.format("Successfully delivered %d alert(s) to %s", success_count, target_jid)
        });
    elseif success_count > 0 then
        response.status_code = 207; -- Multi-Status (partial success)
        return json.encode({
            status = "partial",
            message = string.format("Delivered %d alert(s), %d failed", success_count, fail_count)
        });
    else
        response.status_code = 500;
        return json.encode({
            status = "error",
            message = "Failed to deliver all alerts"
        });
    end
end

-- ============================================================================
-- MODULE INITIALIZATION
-- ============================================================================

-- Register the HTTP endpoint with Prosody
module:provides("http", {
    route = {
        -- GET request returns a simple info message
        ["GET"] = function(event)
            return string.format("Webhook to JID Module v%s - POST to /webhook_to_jid/{target_jid}", MODULE_VERSION);
        end;
        -- POST requests with any path are handled by the webhook handler
        ["POST /*"] = handle_webhook;
    };
});

module:log("info", "Webhook to JID module v%s loaded. Endpoint: /webhook_to_jid/{target_jid}", MODULE_VERSION);

if use_template then
    if message_template then
        module:log("info", "Using custom message template");
    else
        module:log("warn", "webhook_to_jid_use_template is true but no template provided, using built-in formatting");
        use_template = false;
    end
end

if debug_mode then
    module:log("info", "Debug mode enabled - will log payloads and formatted messages");
end