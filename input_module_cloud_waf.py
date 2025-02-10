import os
import time
import datetime
import json
import http.client
import urllib.parse
import re
import logging
import traceback


# --------------------------------------------------
# Set up a module-level logger.
# --------------------------------------------------
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)
# If you want to see logs in console (for debug), uncomment below:
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s]: %(message)s')
# console_handler.setFormatter(formatter)
# LOGGER.addHandler(console_handler)


def validate_input(helper, definition):
    """
    Splunk-specific function stub for input validation.
    Placeholder if you need to do Splunk modular input validation.
    """
    pass


def create_https_connection(credentials, host):
    """
    Create an HTTPS connection, optionally using a proxy if enabled.

    :param credentials: A dictionary containing credentials and proxy configuration.
    :param host: The main host you want to connect to (e.g., "portal-ng.radwarecloud.com").
    :return: An http.client.HTTPSConnection object.
    """
    if credentials.get('use_proxy'):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'], credentials['proxy_port'])
        conn.set_tunnel(host, port=443)
    else:
        conn = http.client.HTTPSConnection(host, 443, timeout=10)
    return conn


def get_tenant_id(helper, credentials):
    """
    Retrieve the tenant entity ID from the Radware Cloud portal.

    :param helper: Splunk helper object.
    :param credentials: A dictionary containing credentials, Bearer token, and other details.
    :return: String representing the tenantEntityId.
    :raises: SystemExit if the HTTP request fails or any error occurs.
    """
    LOGGER.debug("Starting get_tenant_id with email: %s", credentials["email_address"])
    headers = {"Authorization": "Bearer %s" % credentials["Bearer"]}

    conn = create_https_connection(credentials, "portal-ng.radwarecloud.com")

    try:
        conn.request("GET", "/v1/users/me/summary", headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            LOGGER.error("Failed TenantID with response => %d : %s", response.status, response.reason)
            raise SystemExit(2)
        data = json.loads(response.read().decode("utf8"))
        LOGGER.debug("TenantID obtained: %s", data["tenantEntityId"])
        LOGGER.debug("get_tenant_id obtained successfully.")
        return data["tenantEntityId"]
    except Exception:
        LOGGER.error("Error occurred on getting the TenantID from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())
        raise SystemExit(2)


def get_application_ids(credentials):
    """
    Collect application IDs for Bot events from Radware Cloud.

    :param credentials: A dictionary containing credentials (Bearer, TenantID, etc.).
    :return: A list of application ID dictionaries: [{"applicationId": <id>}, ...].
    :raises: SystemExit if the HTTP request fails or any error occurs.
    """
    LOGGER.debug("Starting get_application_ids with email: %s", credentials["email_address"])
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        "requestEntityids": credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": "SplunkCollector/1.8.4"
    }

    conn = create_https_connection(credentials, "portal-ng.radwarecloud.com")

    try:
        conn.request("GET", "/v1/gms/applications", headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            LOGGER.error("Failed collecting application IDs => %d : %s", response.status, response.reason)
            log_out(credentials)
            raise SystemExit(2)
        response_body = json.loads(response.read().decode("utf8"))
        LOGGER.debug("Complete response: %s", json.dumps(response_body, indent=4))
        application_ids = [{"applicationId": app["id"]} for app in response_body.get("content", [])]
        LOGGER.debug("Fetched %d application IDs successfully.", len(application_ids))
        LOGGER.debug("Application IDs are: %s", json.dumps(application_ids))
        LOGGER.debug("get_application_ids obtained successfully.")
        return application_ids
    except Exception:
        LOGGER.error("Error occurred collecting application IDs.\n%s", traceback.format_exc())
        raise SystemExit(2)


def get_session_token(credentials):
    """
    Obtain an Okta session token using the user's email and password.

    :param credentials: A dictionary containing 'email_address' and 'password'.
    :return: None; updates credentials dict in-place with "sessionToken".
    :raises: SystemExit if the HTTP request fails or any error occurs.
    """
    LOGGER.debug("Starting get_session_token with email: %s", credentials["email_address"])
    conn = create_https_connection(credentials, "radware-public.okta.com")

    payload = json.dumps({
        "username": credentials["email_address"],
        "password": credentials["password"],
        "options": {
            "multiOptionalFactorEnroll": True,
            "warnBeforePasswordExpired": True
        }
    })
    headers = {
        'Content-Type': "application/json",
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'SplunkCollector/1.8.4'
    }

    try:
        conn.request("POST", "/api/v1/authn", payload, headers)
        res = conn.getresponse()
        if res.status != 200:
            LOGGER.error("Failed Session with response => %d : %s", res.status, res.reason)
            raise SystemExit(2)
        data = json.loads(res.read().decode("utf-8"))
        credentials["sessionToken"] = data["sessionToken"]
        LOGGER.debug("Session token obtained successfully.")
    except Exception:
        LOGGER.error("Error occurred getting the Session token from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())
        raise SystemExit(2)


def get_authorization_token(credentials):
    """
    Obtain the Bearer (Authorization) token from Okta using the session token.

    :param credentials: A dictionary containing the sessionToken.
    :return: None; updates credentials dict in-place with "Bearer" token.
    :raises: SystemExit if the HTTP request fails or any error occurs.
    """
    LOGGER.debug("Starting get_authorization_token with email: %s", credentials["email_address"])
    conn = create_https_connection(credentials, "radware-public.okta.com")
    headers = {
        "Content-type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "SplunkCollector/1.8.4"
    }

    authorize_path = (
        "/oauth2/aus7ky2d5wXwflK5N1t7/v1/authorize?client_id=M1Bx6MXpRXqsv3M1JKa6"
        "&nonce=n-0S6_WzA2M&prompt=none"
        "&redirect_uri=https%3A%2F%2Fportal-ng.radwarecloud.com%2F"
        "&response_mode=form_post&response_type=token"
        "&scope=api_scope&sessionToken={session_token}&state=parallel_af0ifjsldkj"
    ).format(session_token=credentials["sessionToken"])

    try:
        conn.request("GET", authorize_path, "", headers)
        res = conn.getresponse()
        if res.status != 200:
            LOGGER.error("Failed Authorization with response => %d : %s", res.status, res.reason)
            raise SystemExit(2)

        # Parse Bearer token from response
        data = res.read()
        set_cookie_header = res.getheader('set-cookie')
        if set_cookie_header:
            result = re.split(r'([^;]+);?', set_cookie_header, re.MULTILINE)
            for cookie in result:
                dt = re.search(r',\sDT=([^;]+);?', cookie, re.MULTILINE)
                sid = re.search(r',\ssid=([^;]+);?', cookie, re.MULTILINE)
                proximity = re.search(r',(.+=[^;]+);?\sEx', cookie, re.MULTILINE)
                sess_id = re.search(r'JSESSIONID=([^;]+);?', cookie, re.MULTILINE)
                if proximity:
                    credentials["proximity"] = proximity.group(1)
                elif dt:
                    credentials["DT"] = dt.group(1)
                elif sid:
                    credentials["sid"] = sid.group(1)
                elif sess_id:
                    credentials["JSESSIONID"] = sess_id.group(1)

        # The access_token is inside the HTML form returned
        # name="access_token" value="<token>"
        content_decoded = data.decode('unicode_escape')
        credentials["Bearer"] = content_decoded.split('name="access_token" value="')[1].split('"')[0]
        LOGGER.debug("get_authorization_token obtained successfully.")
    except Exception:
        LOGGER.error("Error occurred on getting the Authorization from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())
        raise SystemExit(2)


def log_out(credentials):
    """
    Perform logout from Okta (delete session). Typically called before system exit.

    :param credentials: A dictionary containing tokens, session ID, etc.
    :return: None
    """
    LOGGER.debug("Attempting to log out.")
    headers = {
        'Referer': 'https://portal-ng.radwarecloud.com',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'Cookie': "JSESSIONID={0},DT={1},sid={2},{3},t=default".format(
            credentials.get("JSESSIONID", ""),
            credentials.get("DT", ""),
            credentials.get("sid", ""),
            credentials.get("proximity", "")
        )
    }

    conn = create_https_connection(credentials, "radware-public.okta.com")

    try:
        conn.request("DELETE", "/api/v1/sessions/me", headers=headers)
        res = conn.getresponse()
        if res.status != 204:
            LOGGER.error("Failed LogOut with response => %d : %s", res.status, res.reason)
        else:
            LOGGER.debug("LogOut successfully.")
        conn.close()
    except Exception:
        LOGGER.error("Error occurred on log_out from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())


def get_activity(credentials, timelower, timeupper):
    """
    Get user activity logs.

    :param credentials: A dictionary containing credentials.
    :param timelower: Lower bound epoch time (ms).
    :param timeupper: Upper bound epoch time (ms).
    :return: The raw byte string of activity logs (JSON).
    :raises: SystemExit if the request fails or any error occurs.
    """
    conn = create_https_connection(credentials, "portal-ng.radwarecloud.com")
    payload = (
        '{"criteria":[{"type":"timeFilter","field":"startDate","includeLower":true,"includeUpper":true,'
        '"upper":' + timeupper + ',"lower":' + timelower + '}],'
        '"pagination":{"page":0,"size":100000},'
        '"order":[{"type":"Order","order":"DESC","field":"startDate"}]}'
    )

    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': str(len(payload)),
        'Content-Type': 'application/json;charset=UTF-8',
        'User-Agent': 'SplunkCollector/1.8.4'
    }

    try:
        conn.request("POST", "/v1/userActivityLogs/reports/", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            return res.read()
        else:
            LOGGER.error("Failed get_activity => %d : %s, Body: %s",
                         res.status, res.reason, res.read().decode())
            log_out(credentials)
            raise SystemExit(2)
    except Exception:
        LOGGER.error("Error occurred on getting activity events from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())
        raise SystemExit(2)


def get_security_events(credentials, timelower, timeupper, page):
    """
    Get WAF/security events (e.g., advanced rules, geo-blocking, etc.).

    :param credentials: A dictionary containing credentials.
    :param timelower: Lower bound epoch time (ms).
    :param timeupper: Upper bound epoch time (ms).
    :param page: Which page of paginated results to retrieve.
    :return: A list of dictionaries representing security events.
    :raises: SystemExit if the request fails or any error occurs.
    """
    LOGGER.debug("Starting get_security_events on page %s", page)
    conn = create_https_connection(credentials, "portal-ng.radwarecloud.com")

    payload = (
        '{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,'
        '"includeUpper":true,"upper":' + timeupper + ',"lower":' + timelower + '}],'
        '"pagination":{"page":' + str(page) + ',"size":100},'
        '"order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"LONG"}]}'
    )
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': str(len(payload)),
        'Content-Type': 'application/json;charset=UTF-8'
    }

    try:
        conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            appdata = json.loads(res.read())
            LOGGER.debug("Total WAF events (metaData): %s", appdata['metaData']['totalHits'])
            LOGGER.debug("get_security_events obtained successfully.")
            return appdata['data']
        else:
            LOGGER.error("Failed getEvents => %d : %s", res.status, res.reason)
            log_out(credentials)
            raise SystemExit(2)
    except Exception:
        LOGGER.error("Error occurred on getting security events from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())
        raise SystemExit(2)


def get_ddos_events(credentials, timelower, timeupper, page):
    """
    Retrieve DDoS events.

    :param credentials: A dictionary containing credentials.
    :param timelower: Lower bound epoch time (ms).
    :param timeupper: Upper bound epoch time (ms).
    :param page: Which page of paginated results to retrieve.
    :return: A list of dictionaries representing DDoS events.
    :raises: SystemExit if the request fails or any error occurs.
    """
    LOGGER.debug("Starting get_ddos_events on page %s", page)
    conn = create_https_connection(credentials, "portal-ng.radwarecloud.com")

    payload = (
        '{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,'
        '"upper":' + timeupper + ',"lower":' + timelower + '}],'
        '"pagination":{"page":' + str(page) + ',"size":100},'
        '"order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'
    )
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': str(len(payload)),
        'Content-Type': 'application/json;charset=UTF-8'
    }

    try:
        conn.request("POST", "/mgmt/monitor/reporter/reports-ext/SYSTEM_ATTACK", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            appdata = json.loads(res.read())
            LOGGER.debug("Total DDoS events (metaData): %d", appdata['metaData']['totalHits'])
            LOGGER.debug("get_ddos_events obtained successfully.")
            return appdata['data']
        else:
            LOGGER.error("Failed get_ddos_events => %d : %s", res.status, res.reason)
            log_out(credentials)
            raise SystemExit(2)
    except Exception:
        LOGGER.error("Error occurred on getting DDoS events from Cloud AppSec portal-ng.\n%s",
                     traceback.format_exc())
        raise SystemExit(2)


def get_bot_events(credentials, timelower, timeupper, application_ids, page):
    """
    Retrieve bot events from Radware Bot Manager.

    :param credentials: A dictionary containing credentials.
    :param timelower: Lower bound epoch time (ms).
    :param timeupper: Upper bound epoch time (ms).
    :param application_ids: Dictionary containing "applicationIds": [{applicationId: ...}, ...]
    :param page: Which page of paginated results to retrieve.
    :return: If successful, a dictionary with bot events. Returns 0, -1, or 2 in certain error/no-data conditions.
    """
    LOGGER.debug("Starting get_bot_events on page %s", page)
    conn = create_https_connection(credentials, "portal-ng.radwarecloud.com")

    if not application_ids or "applicationIds" not in application_ids:
        LOGGER.error("No application IDs available in 'applicationIds'. Check your account.")
        return 0

    # Construct the payload
    # The initial part is the "applicationIds", plus a "requestParameters" section
    # that includes pagination, start/end times, etc.
    base_json = {
        "applicationIds": application_ids["applicationIds"],
        "requestParameters": {
            "sort_order": "desc",
            "page_size": 2500,
            "page": int(page),
            "starttime": timelower,
            "endtime": timeupper
        }
    }
    payload = json.dumps(base_json)
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': str(len(payload)),
        'Content-Type': 'application/json;charset=UTF-8',
        'User-Agent': 'SplunkCollector/1.8.4'
    }

    try:
        LOGGER.debug("Sending request to get Bot Events with payload: %s", payload)
        conn.request("POST", "/antibot/reports/v2/fetch/bad-bot/iia-list", payload, headers=headers)
        res = conn.getresponse()
        LOGGER.debug("Response code: %d with Content-Length %s", res.status, res.headers.get("Content-Length", ""))
        if res.status in (400, 502):
            return -1

        if res.headers.get("Content-Length") == "0":
            return 0

        data = json.loads(res.read())
        # data["page"] might be 0 if no data
        if "page" in data and data["page"] == 0:
            return 0

        if res.status == 200:
            LOGGER.debug("get_bot_events obtained successfully.")
            return data

        LOGGER.error("Unexpected response while fetching bot events: %s", data)
        log_out(credentials)
        return 2

    except Exception:
        LOGGER.error("Error occurred on getting Bot events for application IDs %s.\n%s",
                     application_ids, traceback.format_exc())
        return -1


def format_bot_event(helper, ew, bulk_events, page):
    """
    Format and write bot events into Splunk using helper.new_event(...).

    :param helper: Splunk helper object.
    :param ew: Splunk event writer object.
    :param bulk_events: Dictionary of bot events with 'results' key.
    :param page: The current page being processed.
    """
    LOGGER.debug("Starting format_bot_event for page %s", page)
    if "results" not in bulk_events:
        return

    for idx, event_item in enumerate(bulk_events["results"]):
        # The time is in milliseconds
        epoch_sec = int(event_item['time']) / 1000.0
        dt_str = str(datetime.datetime.fromtimestamp(epoch_sec))
        build_event = (
            f"_time={dt_str},"
            f"event_type=bot,"
            f"action={event_item.get('response_code','')},"
            f'uri="{event_item.get("url","")}",'
            f"srcIP={event_item.get('ip','')},"
            f"category={event_item.get('bot_category','')},"
            f'referrer="{event_item.get("referrer","")}",'
            f"cookie={event_item.get('session_cookie','')},"
            f"violation={event_item.get('violation_reason','')},"
            f"country={event_item.get('country_code','')},"
            f"fqdn={event_item.get('site','')},"
            f"transId={event_item.get('tid','')},"
            f"user-agent={event_item.get('ua','')}"
        )
        event = helper.new_event(
            source=helper.get_input_type(),
            index=helper.get_output_index(),
            sourcetype=helper.get_sourcetype(),
            data=build_event
        )
        ew.write_event(event)


def format_security_event(helper, ew, bulk_events, tenant_id):
    """
    Format and write security (WAF) events into Splunk using helper.new_event(...).

    :param helper: Splunk helper object.
    :param ew: Splunk event writer object.
    :param bulk_events: List of events (appdata['data']) from get_security_events.
    :param tenant_id: The tenant ID string.
    """
    LOGGER.debug("Starting format_security_event with %d events", len(bulk_events))
    ua_pattern = r'User-Agent:\s(.+)?'
    referer_pattern = r'Referer:\s(.+)?'

    for event_obj in bulk_events:
        row = event_obj.get('row', {})
        try:
            # The universal part: time
            epoch_sec = int(row.get('receivedTimeStamp', 0)) / 1000.0
            dt_str = str(datetime.datetime.fromtimestamp(epoch_sec))
            build_event = f"_time={dt_str},event_type=security,"

            # Common fields
            def add_field_if_present(key_name, label=None, quotes=False):
                """
                Helper function to add key/value if present in `row`.
                label = name in final string if different from key_name
                quotes = True to wrap the value in quotes
                """
                actual_label = label if label else key_name
                if key_name in row:
                    value = str(row[key_name])
                    if quotes:
                        # Replace newlines in value
                        value = re.sub(r'[\n\r]+', ' ', value)
                        # Escape double-quotes
                        value = value.replace('"', '\\"')
                        return f'{actual_label}="{value}",'
                    return f"{actual_label}={value},"
                return ""

            build_event += add_field_if_present('directory')
            build_event += add_field_if_present('passive')
            build_event += add_field_if_present('protocol')
            build_event += add_field_if_present('details', 'details', quotes=True)
            build_event += f"action={row.get('action','')},"

            if 'uri' in row:
                build_event += f"uri={row['uri']},"

            # IP and ports
            build_event += f"srcIP={row.get('externalIp','')},"
            build_event += f"srcPort={row.get('sourcePort','')},"
            if 'destinationPort' in row:
                build_event += f"dstPort={row['destinationPort']},"

            # Additional fields
            build_event += f"method={row.get('method','')},"
            build_event += f"type={row.get('violationType', row.get('eventType',''))},"
            build_event += f"severity={row.get('severity','')},"
            build_event += f"tenantid={tenant_id},"
            build_event += f"transId={row.get('transId','')}"

            # Optional request parsing for user-agent, referer, cookie, etc.
            request_val = row.get('request', '')
            if request_val:
                user_agent = re.search(ua_pattern, request_val, re.MULTILINE)
                if user_agent:
                    build_event += f",user-agent={user_agent.group(1).strip()}"
                referer = re.search(referer_pattern, request_val, re.MULTILINE)
                if referer:
                    build_event += f",referer={referer.group(1).strip()}"
                # If you want other header fields:
                cookie_match = re.search(r'^Cookie:\s(.+)?\r\n', request_val, re.MULTILINE)
                if cookie_match:
                    build_event += f",cookie={cookie_match.group(1).strip()}"

                x_rdwr_port = re.search(r'^X-RDWR-PORT:\s(.+)?\r\n', request_val, re.MULTILINE)
                if x_rdwr_port:
                    build_event += f",x-rdwr-port={x_rdwr_port.group(1).strip()}"

                x_rdwr_port_mm_orig = re.search(
                    r'^X-RDWR-PORT-MM-ORIG-FE-PORT:\s(.+)?\r\n', request_val, re.MULTILINE
                )
                if x_rdwr_port_mm_orig:
                    build_event += f",x-rdwr-port-mm-orig-fe-port={x_rdwr_port_mm_orig.group(1).strip()}"

                x_rdwr_port_mm = re.search(r'^X-RDWR-PORT-MM:\s(.+)?\r\n', request_val, re.MULTILINE)
                if x_rdwr_port_mm:
                    build_event += f",x-rdwr-port-mm={x_rdwr_port_mm.group(1).strip()}"

            # If 'headers' might contain 'Referer' or something else
            headers_val = row.get('headers', '')
            if headers_val:
                referer_in_header = re.search(referer_pattern, headers_val, re.MULTILINE)
                if referer_in_header:
                    build_event += f",referer={referer_in_header.group(1).strip()}"

            # Attempt to unify any final differences
            if 'module' in row:
                build_event += f",module={row['module']}"
            if 'title' in row:
                build_event += f",title={row['title']}"
            if 'webApp' in row:
                build_event += f",application={row['webApp']}"
            if 'violationCategory' in row:
                build_event += f",category={row['violationCategory']}"
            if 'host' in row:
                build_event += f",fqdn={row['host']}"

            event = helper.new_event(
                source=helper.get_input_type(),
                index=helper.get_output_index(),
                sourcetype=helper.get_sourcetype(),
                data=build_event
            )
            ew.write_event(event)

        except Exception:
            LOGGER.error("Error occurred formatting security event from Cloud AppSec portal.\nEvent: %s\n%s",
                         event_obj, traceback.format_exc())
            # Optionally continue or raise
            continue


def format_activity(helper, ew, bulk_activity):
    """
    Format and write user activity logs into Splunk.

    :param helper: Splunk helper object.
    :param ew: Splunk event writer object.
    :param bulk_activity: Dictionary with key 'userActivityLogs' containing a list of logs.
    """
    LOGGER.debug("Starting format_activity")
    logs = bulk_activity.get('userActivityLogs', [])
    for item in logs:
        epoch_sec = int(item.get('startDate', 0)) / 1000.0
        dt_str = str(datetime.datetime.fromtimestamp(epoch_sec))
        build_event = (
            f"_time={dt_str},"
            f"event_type=activity,"
            f"id={item.get('trackingId','')},"
            f"user={item.get('userEmail','')},"
            f"details={item.get('processTypeText','')},"
            f"status={item.get('status','')},"
            f"userIP={item.get('userIp','')},"
            f"country={item.get('userCountry','')},"
            f"activity={item.get('activityType','')},"
            f"user-agent={item.get('userAgent','')}"
        )
        event = helper.new_event(
            source=helper.get_input_type(),
            index=helper.get_output_index(),
            sourcetype=helper.get_sourcetype(),
            data=build_event
        )
        ew.write_event(event)


def format_ddos_event(helper, ew, bulk_events):
    """
    Format and write DDoS events into Splunk.

    :param helper: Splunk helper object.
    :param ew: Splunk event writer object.
    :param bulk_events: List of DDoS event dictionaries.
    """
    LOGGER.debug("Starting format_ddos_event with %d events", len(bulk_events))
    for item in bulk_events:
        row = item.get('row', {})
        epoch_sec = int(row.get('receivedTimeStamp', 0)) / 1000.0
        dt_str = str(datetime.datetime.fromtimestamp(epoch_sec))
        build_event = (
            f"_time={dt_str},"
            f"event_type=ddos,"
            f"action={row.get('action','')},"
            f"srcIP={row.get('source_address','')},"
            f"srcPort={row.get('source_port','')},"
            f"dstIP={row.get('destination_address','')},"
            f"dstPort={row.get('destination_port','')},"
            f"protocol={row.get('protocol','')},"
            f"type={row.get('attack_name','')},"
            f"category={row.get('category','')},"
            f"severity={row.get('severity','')},"
        )
        if 'packet_count' in row:
            build_event += f"packets={row['packet_count']},"
        build_event += f"transId={row.get('id','')}"

        event = helper.new_event(
            source=helper.get_input_type(),
            index=helper.get_output_index(),
            sourcetype=helper.get_sourcetype(),
            data=build_event
        )
        ew.write_event(event)


# -------------------------------------------------------------------------------------
# Handling last-run-time tracking in a local file
# -------------------------------------------------------------------------------------
def get_last_run_time():
    """
    Read the last run time from a local file. If not present, create it with the current time.

    :return: An integer representing the last run epoch time in milliseconds.
    """
    file_path = '/opt/splunk/var/log/splunk/last_run_time.txt'
    if not os.path.exists(file_path):
        # If the file does not exist, initialize with current time
        last_run_time = int(time.time() * 1000)
        save_last_run_time(last_run_time)
        return last_run_time

    try:
        with open(file_path, 'r') as file:
            last_run_time = int(file.read().strip())
            return last_run_time
    except (ValueError, FileNotFoundError):
        # If there's an error reading the file, default to now
        last_run_time = int(time.time() * 1000)
        save_last_run_time(last_run_time)
        return last_run_time


def save_last_run_time(timestamp):
    """
    Persist the last run time to a local file.

    :param timestamp: The epoch time in milliseconds to store.
    """
    file_path = '/opt/splunk/var/log/splunk/last_run_time.txt'
    with open(file_path, 'w') as file:
        file.write(str(timestamp))


# -------------------------------------------------------------------------------------
# Main function for Splunk input collection
# -------------------------------------------------------------------------------------
def collect_events(helper, ew):
    """
    Main entry point for Splunk to collect events from Radware Cloud AppSec.

    :param helper: The Splunk add-on helper object.
    :param ew: The Splunk event writer object.
    """
    stanza = helper.get_input_stanza()
    interval = 300  # default fallback
    for key in stanza:
        # You can do more robust retrieval of the interval if needed
        interval = int(stanza[key].get('interval', 300))

    now = int(time.time() * 1000)
    past = get_last_run_time()

    # If it's been more than 10 minutes since last run, reset 'past' to (now - interval)
    if now - past > 600000:  # 10 minutes in ms
        past = now - (interval * 1000)
        file_path = '/opt/splunk/var/log/splunk/last_run_time.txt'
        if os.path.exists(file_path):
            os.remove(file_path)

    # Save current 'now' so next run sees it as 'past'
    save_last_run_time(now)

    LOGGER.debug("Now Time: %s", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now / 1000)))
    LOGGER.debug("Past Time: %s", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(past / 1000)))

    credentials = {
        "sessionToken": "",
        "Bearer": "",
        "email_address": helper.get_arg('email_address'),
        "password": helper.get_arg('password'),
        "proxy_ip": helper.get_arg('proxy_ip'),
        "proxy_port": int(helper.get_arg('proxy_port')),
        "TenantID": "",
        "JSESSIONID": "",
        "DT": "",
        "sid": "",
        "proximity": "",
        "use_proxy": False
    }
    # Determine if proxy is in use
    if credentials['proxy_ip'] != "0.0.0.0" and credentials['proxy_port'] != 0:
        credentials['use_proxy'] = True

    # Decide which logs to fetch
    type_logs = helper.get_arg('type_of_logs')  # e.g. a list/dict from multi-select
    if not type_logs:
        LOGGER.error("Type of logs not specified.")
        return

    # Acquire tokens and tenant
    try:
        get_session_token(credentials)
        get_authorization_token(credentials)
        credentials["TenantID"] = get_tenant_id(helper, credentials)
    except SystemExit as e:
        # If there's a system exit from these calls, we can optionally re-raise or return
        LOGGER.error("Unable to acquire tokens/tenant. Exiting collect_events.")
        return

    # Start fetching logs
    try:
        # WAF events
        if 'waf_events' in type_logs:
            page = 0
            while True:
                bulk_events = get_security_events(credentials, str(past), str(now), page)
                if not bulk_events:
                    break
                format_security_event(helper, ew, bulk_events, credentials["TenantID"])
                page += 1
                LOGGER.debug("Processed WAF page: %d", page)

        # DDoS events
        if 'ddos_events' in type_logs:
            page = 0
            while True:
                bulk_events = get_ddos_events(credentials, str(past), str(now), page)
                if not bulk_events:
                    break
                format_ddos_event(helper, ew, bulk_events)
                page += 1
                LOGGER.debug("Processed DDoS page: %d", page)

        # Bot events
        if 'bot_events' in type_logs:
            application_ids = {"applicationIds": get_application_ids(credentials)}
            page = 1
            while True:
                bulk_events = get_bot_events(credentials, str(past), str(now), application_ids, str(page))
                if not isinstance(bulk_events, dict):
                    if bulk_events in (0, -1, 2):
                        # 0 => no more data or no apps
                        # -1 => error/bad page
                        # 2 => error from server
                        break
                format_bot_event(helper, ew, bulk_events, page)
                LOGGER.debug("Processed Bot page: %d", page)
                if "results" not in bulk_events or len(bulk_events["results"]) == 0:
                    break
                page += 1

        # User activity
        if 'user_activity' in type_logs:
            raw_activity = get_activity(credentials, str(past), str(now))
            if raw_activity:
                parsed_activity = json.loads(raw_activity)
                format_activity(helper, ew, parsed_activity)

    except SystemExit as e:
        LOGGER.error("A system exit occurred during log retrieval: %s", e)
    except Exception:
        LOGGER.error("Unexpected error while fetching events.\n%s", traceback.format_exc())
    finally:
        # Attempt to log out to clean up session
        log_out(credentials)
        LOGGER.debug("Finished one cycle of events.")
