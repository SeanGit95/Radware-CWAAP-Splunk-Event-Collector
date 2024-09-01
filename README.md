# Radware-CWAAP-Splunk-Event-Collector

## Overview

Radware Cloud WAF event collector allows you to automatically collect all security events from the Cloud WAF portal. It is developed using API calls, enabling you to receive events directly without relying on any external tool.

## Installation and Setup

Once the Splunk app is installed, follow these steps:

1. **Create a New Input**:
   - Go to the App, and under ‘Input,’ click on ‘Create New Input.’
   - Enter the credentials of the Cloud WAF API user.
   - Provide a Name and set the Interval for data collection.

2. **Optional Configuration**:
   - On the Configuration tab, you can manage the log level (Default is INFO – all logs).

3. **Verify Event Collection**:
   - (Recommended) Go to the search tab and check for security events to ensure the event collector is working properly. Use ‘*’ to see all security events.

## Features

- **Proxy Support**: The collector can be configured to use a proxy if required. Ensure to set the `proxy_ip` and `proxy_port` correctly.
- **Multiple Event Types**: Supports collection of WAF events, DDoS events, Bot events, and User Activity logs.
- **Log Management**: The collector allows you to manage the log level for better debugging and information tracking.
- **Session Management**: Handles session tokens and authorization tokens securely for interacting with Radware's Cloud WAF API.

## Configuration Details

- **Proxy Configuration**:
  - Set `proxy_ip` and `proxy_port` to your proxy server's details. If either of these fields is left as the default (`0.0.0.0` or `0`), the collector will not use a proxy.
  
- **Credentials**:
  - You must provide the `email_address` and `password` for the Cloud WAF API user. These credentials are used to obtain session and authorization tokens required for API communication.

- **Event Collection**:
  - The collector will retrieve events based on the time interval set. It supports the collection of multiple event types:
    - `waf_events`: WAF security events
    - `ddos_events`: DDoS security events
    - `bot_events`: Bot-related events
    - `user_activity`: User activity logs
  
- **Last Run Time Tracking**:
  - The collector tracks the last successful run time to ensure that events are collected only once. This time is stored in `/opt/splunk/var/log/splunk/last_run_time.txt`.

## Error Handling

- **Invalid Responses**:
  - The collector will log errors and exit if it receives an invalid response (e.g., status codes other than 200) from the Radware Cloud WAF API.

- **Session Timeouts**:
  - If the session is too old (over 10 minutes), the collector will reset the session to ensure continuity.

## Usage

- **Starting the Collection**:
  - Ensure all necessary configurations (e.g., credentials, proxy settings) are in place.
  - Set the appropriate event types you wish to collect.
  - The collector will automatically start collecting events at the defined intervals.

## Logging

- The app uses Python's `logging` module to provide detailed logs for debugging and operational tracking. Adjust the logging level according to your needs on the Configuration tab in Splunk.
