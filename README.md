# Radware-CWAAP-Splunk-Event-Collector

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
