# Radware-CWAAP-Splunk-Event-Collector

## Overview

Radware Cloud WAF event collector allows you to automatically collect all security events from the Cloud WAF portal. It uses API calls to retrieve events directly without relying on any external tools. This repository provides an updated Python codebase with enhanced error handling, structured logging, and proxy support.

## Installation and Setup

1. **Install the Splunk App**:
   - Place the app folder into Splunk's `etc/apps` directory (or install via UI). Restart Splunk if needed.

2. **Create a New Input**:
   - Under the app's configuration, go to 'Inputs' and click on 'Create New Input.'
   - Enter the credentials of the Cloud WAF API user (email and password).
   - Provide an Input Name and set the Interval for data collection (in seconds).
   - Select the event types you wish to collect (WAF events, DDoS events, Bot events, and/or User Activity).

3. **Optional Configuration**:
   - In the Configuration tab, manage your log level (default is `INFO`).
   - If needed, configure the proxy details (`proxy_ip` and `proxy_port`).

4. **Verify Event Collection**:
   - Use Splunk's Search & Reporting interface to verify events are being ingested properly.
   - For instance, run a simple `index=<your_index> sourcetype=<your_sourcetype>` to see if data is present.

## Features

- **Proxy Support**: The collector can be configured to use an HTTPS proxy if required. Set `proxy_ip` and `proxy_port` accordingly.
- **Multiple Event Types**: Collects data for WAF, DDoS, Bot, and User Activity logs.
- **Enhanced Logging**: Uses Python’s logging module for better debugging. Adjust the logging level (e.g., DEBUG, INFO) in Splunk’s Configuration.
- **Session & Authorization Handling**: Automatically manages session tokens and Okta authorization.
- **Last Run Time Tracking**: Keeps track of the last run time in a local file (`/opt/splunk/var/log/splunk/last_run_time.txt`) to avoid duplicating events.

## Configuration Details

- **Proxy Configuration**:
  - `proxy_ip` and `proxy_port` must both be set to non-default values (`0.0.0.0` and `0`) to enable proxy usage.
  - If either is left at default, no proxy is used.

- **Credentials**:
  - Required parameters: `email_address` and `password` (for Cloud WAF API user).
  - The collector obtains both a session token and an authorization (Bearer) token automatically.

- **Event Collection**:
  - The collector retrieves events in a time window from the previous run time to the current time.
  - You can collect multiple event types simultaneously by selecting them in the input configuration.
  - Event types:
    - `waf_events`: Security events from WAF modules
    - `ddos_events`: DDoS security events
    - `bot_events`: Bot attack events
    - `user_activity`: User Activity logs

- **File-Based Tracking**:
  - The collector stores a timestamp of its last successful run in `/opt/splunk/var/log/splunk/last_run_time.txt`.
  - If more than 10 minutes have passed since the last run, the collector automatically resets the time window.

## Error Handling

- The collector logs detailed error messages if API requests fail or return unexpected responses (e.g., status codes other than 200).
- All errors are logged to help you quickly identify issues (e.g., invalid credentials, proxy issues, etc.).

## Usage

1. **Start the Collection**:
   - Once the input is created, Splunk will automatically schedule the collector to run at your chosen interval.
   - Confirm events are ingested by checking your Splunk search results.

2. **Adjust Logging**:
   - Use the Configuration tab in Splunk or edit the app’s config file to switch between DEBUG, INFO, WARN, or ERROR.

3. **Troubleshooting**:
   - Check Splunk’s internal logs (e.g., `splunkd.log`) and the logs from this app if no data appears.
   - Verify your Cloud WAF credentials and ensure that the user has the correct privileges.
   - If using a proxy, confirm that the proxy is reachable.

## Contributing

Feel free to submit issues or pull requests to improve functionality or resolve bugs. This code is provided as-is and is maintained by the community.
