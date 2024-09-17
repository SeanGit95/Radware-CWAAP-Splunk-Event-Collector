import os
import sys
import time
import datetime
import json
import http.client, urllib.parse, urllib.request
import re
import logging
import traceback

def validate_input(helper, definition):
    pass
def getTenantID(helper,credentials):
    logging.debug("Starting getTenantID with email: %s", credentials["email_address"])
    headers = {"Authorization": "Bearer %s" % credentials["Bearer"]}
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    try:
        conn.request("GET","/v1/users/me/summary",headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            logging.error("Failed TenantID with response => %d : %s",response.status,response.reason)
            exit(2)
        else:
            data= json.loads(response.read().decode("utf8"))
            logging.info("TenantID obtained: %s", data["tenantEntityId"])
            logging.debug("getTenantID obtained successfully.")
            return data["tenantEntityId"]
    except:
        logging.error("Error occurred on getting the TenantID from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)
def getApplicationIDs(credentials):
    logging.debug("Starting getApplicationIDs with email: %s", credentials["email_address"])
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        "requestEntityids": credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": "SplunkCollector/1.7.8"
    } 
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)      
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    try:
        conn.request("GET", "/v1/gms/applications", headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            logging.error("Failed collecting application IDs => %d : %s", response.status, response.reason)
            LogOut(credentials)
            exit(2)
        else:
            responsebody = json.loads(response.read().decode("utf8"))
            logging.debug("Complete response: %s", json.dumps(responsebody, indent=4))
            application_ids = [{"applicationId": app["id"]} for app in responsebody.get("content", [])]
            logging.info("Fetched %d application IDs successfully.", len(application_ids))
            logging.debug("Application IDs are: %s", json.dumps(application_ids))
            logging.debug("getApplicationIDs obtained successfully.")
            return application_ids
    except:
        logging.error("Error occurred collecting application IDs. %s",traceback.format_exc())
        exit(2)
def getSessionToken(credentials):
    logging.debug("Starting getSessionToken with email: %s", credentials["email_address"])
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("radware-public.okta.com", port=443)
    else:
        conn = http.client.HTTPSConnection("radware-public.okta.com")
    payload = "{\"username\":\"" + credentials["email_address"] + "\",\"password\":\"" + credentials["password"] + "\",\"options\":{ \"multiOptionalFactorEnroll\": true,\"warnBeforePasswordExpired\": true}}"
    headers = {'Content-Type': "application/json",'Accept': 'application/json, text/plain, */*','User-Agent':'SplunkCollector/1.7.8'}
    try:
        conn.request("POST", "/api/v1/authn", payload, headers)
        res = conn.getresponse()
        if res.status != 200:
            logging.error("Failed Session with response => %d : %s",res.status,res.reason)
            exit(2)
        else:
            data = res.read()
            oktadata = json.loads(data.decode("utf-8"))
            credentials["sessionToken"] = oktadata["sessionToken"]
        logging.debug("Session token obtained successfully.")
        return 0
    except:
        logging.error("Error occurred on getting the Session token from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)
def getAuthorizationToken(credentials):
    logging.debug("Starting getAuthorizationToken with email: %s", credentials["email_address"])
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("radware-public.okta.com", port=443)
    else:
        conn = http.client.HTTPSConnection("radware-public.okta.com")
    headers = {"Content-type": "application/json", "Accept": "application/json, text/plain, */*","User-Agent": "SplunkCollector/1.7.8"}
    try:
        conn.request("GET", "/oauth2/aus7ky2d5wXwflK5N1t7/v1/authorize?client_id=M1Bx6MXpRXqsv3M1JKa6" +
         "&nonce=n-0S6_WzA2M&" +
         "prompt=none&" +
         "redirect_uri=https%3A" + "%2F" + "%2F" + "portal-ng.radwarecloud.com" + "%2F" + "&" +
         "response_mode=form_post&"+
         "response_type=token&" +
         "scope=api_scope&"+
         "sessionToken=" + credentials["sessionToken"] + "&" +
         "state=parallel_af0ifjsldkj","",headers)
        res = conn.getresponse()
        if res.status != 200:
            logging.error("Failed Authorization with response => %d : %s",res.status,res.reason)
            exit(2)
        else:
            data = res.read()
            result = re.split('([^;]+);?', res.getheader('set-cookie'), re.MULTILINE)
            for cookie in result:
                dt = re.search(',\sDT=([^;]+);?', cookie, re.MULTILINE)
                sid = re.search(',\ssid=([^;]+);?', cookie, re.MULTILINE)
                proximity = re.search(',(.+=[^;]+);?\sEx', cookie, re.MULTILINE)
                sessID = re.search(r'JSESSIONID=([^;]+);?', cookie, re.MULTILINE)
                if proximity:
                    credentials["proximity"] = proximity.group(1)
                elif dt:
                    credentials["DT"] = dt.group(1)
                elif sid:
                    credentials["sid"] = sid.group(1)
                elif sessID:
                    credentials["JSESSIONID"] = sessID.group(1)
            credentials["Bearer"] = data.decode('unicode_escape').split('name="access_token" value="')[1].split('"')[0] 
            logging.debug("getAuthorizationToken obtained successfully.")
            return 0
    except:
        logging.error("Error occurred on getting the Authorization from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)
def LogOut(credentials):
    logging.debug("Attempting to log out.")
    uri = "/logout"
    hdrs = {
            'Referer': 'https://portal-ng.radwarecloud.com',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=UTF-8',
            'Cookie': "JSESSIONID={0},DT={1},sid={2},{3},t=default".format(
            credentials["JSESSIONID"], credentials["DT"], credentials["sid"], credentials["proximity"])
            }  
    if (credentials['use_proxy']):
        connection = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        connection.set_tunnel("radware-public.okta.com", port=443)
    else:
        connection = http.client.HTTPSConnection("radware-public.okta.com",443,timeout=10)
    try:
        connection.request("DELETE", "/api/v1/sessions/me", headers=hdrs)
        res = connection.getresponse()
    except:
        logging.error("Error occurred on LogOut from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)
    if res.status != 204:
        logging.error("Failed LogOut with response => %d : %s",res.status,res.reason)
    logging.debug("LogOut successfully.")
    connection.close()
    exit(0)

def getActivity(credentials, timelower, timeupper):
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    payload = '''{"criteria":
                    [{"type":"timeFilter","field":"startDate","includeLower":true,"includeUpper":true,
                        "upper":''' + timeupper + ''',
                        "lower":''' + timelower + '''}],
                    "pagination":{"page":0,"size":100000},
                    "order":[{"type":"Order","order":"DESC","field":"startDate"}]}'''
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': len(payload),
        'Content-Type': 'application/json;charset=UTF-8',
        'User-Agent': 'SplunkCollector/1.7.8'
    }
    try:
        conn.request("POST", "/v1/userActivityLogs/reports/", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            appdata = res.read()
            return appdata
        else:
            logging.error("Failed getActivity with response => %d : %s, Body: %s",res.status,res.reason, res.read().decode())
            LogOut(credentials)
            exit(2)
    except:
        logging.error("Error occurred on getting activity events from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)    
def getSecurityEvents(credentials, timelower, timeupper, page):
    logging.debug("Starting getSecurityEvents")
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    payload = '''{"criteria":
                    [{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,
                        "upper":'''+timeupper+''',
                        "lower":'''+timelower+'''}],
                    "pagination":{"page":'''+str(page)+''',"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"LONG"}]}'''
    headers = {
            "Authorization": "Bearer %s" % credentials["Bearer"],
            'requestEntityids': credentials["TenantID"],
            "Cookie": "Authorization=%s" % credentials["Bearer"],
            'Content-Length': len(payload),
            'Content-Type': 'application/json;charset=UTF-8'
            }
    try:
        conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            appdata = json.loads(res.read())
            logging.info("the total amount of waf events for the API call from metaData: %s", appdata['metaData']['totalHits'])
            logging.debug("getSecurityEvents obtained successfully.")
            return appdata['data']
        else:
            logging.error("Failed getEvents with response => %d : %s",res.status,res.reason)
            LogOut(credentials)
            exit(2)
    except:
        logging.error("Error occurred on getting security events from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)
def getDDoSEvents(credentials, timelower, timeupper, page):
    logging.debug("starting getDDoSEvents.")
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    payload = '''{"criteria":
                    [{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,
                        "upper":''' + timeupper + ''',
                        "lower":''' + timelower + '''}],
                    "pagination":{"page":''' + str(page) + ''',"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': len(payload),
        'Content-Type': 'application/json;charset=UTF-8'
    }
    try:
        conn.request("POST", "/mgmt/monitor/reporter/reports-ext/SYSTEM_ATTACK", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            appdata = json.loads(res.read())
            logging.info("the amount of ddos events for the API call is: %d", appdata['metaData']['totalHits'])
            logging.debug("getDDoSEvents obtained successfully.")
            return appdata['data']
        else:
            logging.error("Failed getDDoSEvents with response => %d : %s", res.status, res.reason)
            LogOut(credentials)
            exit(2)
    except:
        logging.error("Error occurred on getting DDoS events from Cloud AppSec portal-ng. %s",traceback.format_exc())
        exit(2)
def getBotEvents(credentials, timelower, timeupper,applicationID,page):
    logging.debug("starting getBotEvents.")
    data={}
    if (credentials['use_proxy']):
        conn = http.client.HTTPSConnection(credentials['proxy_ip'],credentials['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    if applicationID == "":
        applicationIDs = "\"applicationIds\":[{\"applicationId\":\"" + applicationID +'\"}],'
        logging.error("No application available for the given account : {0!s}".format(applicationIDs))
        logging.error("Response received : {0!s}".format(res))
        return 0
    payload = json.dumps(applicationID)[:-1] +''',"requestParameters":{"sort_order":"desc","page_size":10000,"page":''' + page + ''',"starttime":''' + timelower + ''',"endtime":''' + timeupper + '''}}'''
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': len(payload),
        'Content-Type': 'application/json;charset=UTF-8',
        'User-Agent': 'SplunkCollector/1.7.8'
    }
    conn.request("POST", "/antibot/reports/v2/fetch/bad-bot/iia-list", payload, headers=headers)
    res = conn.getresponse()
    logging.info("Response code from Bot Manager is : %d with Content-Length %d.",res.status,res.headers["Content-Length"])
    logging.info("Body request sent to Bot Manager is : %s.",payload)
    #logging.info("Response received from Bot Manager is : %s.",res.read())
    if res.status == 502 or res.status == 400:
        return -1
    elif res.headers["Content-Length"] == "0":
        return 0
    try :
        data = json.loads(res.read())
        if data["page"] == 0:
            return 0
        elif res.status == 200:
            logging.debug("getBotEvents obtained successfully.")
            return data
        else:
            logging.error(data)
            LogOut(credentials)
            return 2        
    except:
        logging.error("Error occurred on getting Bot events from Cloud AppSec portal on application id : %s. %s",applicationID,traceback.format_exc())
        return -1
def format_bot_event(helper,ew,bulk_events,page):
    item = 0
    build_event = ""
    while (100*(page-1)+item) < bulk_events["total_count"] and item < 100:
        build_event = "_time=" + str(datetime.datetime.fromtimestamp(int(bulk_events["results"][item]['time']) / 1000.0)) + ","
        build_event = build_event + "event_type=" + "bot" + ","
        build_event = build_event + "action=" + str(bulk_events["results"][item]['response_code']) + ","
        build_event = build_event + "uri=\"" + str(bulk_events["results"][item]['url']) + "\","
        build_event = build_event + "srcIP=" + str(bulk_events["results"][item]['ip']) + ","
        build_event = build_event + "category=" + str(bulk_events["results"][item]['bot_category']) + ","
        build_event = build_event + "referrer=\"" + str(bulk_events["results"][item]['referrer']) + "\","
        build_event = build_event + "cookie=" + str(bulk_events["results"][item]['session_cookie']) + ","
        build_event = build_event + "violation=" + str(bulk_events["results"][item]['violation_reason']) + ","
        build_event = build_event + "country=" + str(bulk_events["results"][item]['country_code']) + ","
        build_event = build_event + "fqdn=" + str(bulk_events["results"][item]['site']) + ","
        build_event = build_event + "transId=" + str(bulk_events["results"][item]['tid']) + ","
        build_event = build_event + "user-agent=" + str(bulk_events["results"][item]['ua'])
        event=helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=build_event)
        ew.write_event(event)
        item += 1
    return
def format_security_event(helper, ew, bulk_events, tenantid):
    item = 0
    ua_pattern = 'User-Agent:\s(.+)?'
    referer_pattern = 'Referer:\s(.+)?'
    build_event = ""
    while item < len(bulk_events):
        try:
            if (bulk_events[item]['row']['targetModule'] == "Advanced Rules") or (bulk_events[item]['row']['targetModule'] == "Access-Rules"):
                build_event = "_time=" + str(
                    datetime.datetime.fromtimestamp(int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","
                if 'directory' in bulk_events[item]['row']:
                    build_event = build_event + "directory=" + str(bulk_events[item]['row']['directory']) + ","
                if 'passive' in bulk_events[item]['row']:
                    build_event = build_event + "passive=" + str(bulk_events[item]['row']['passive']) + ","
                if 'protocol' in bulk_events[item]['row']:
                    build_event = build_event + "protocol=" + str(bulk_events[item]['row']['protocol']) + ","
                if 'details' in bulk_events[item]['row']:
                    details_value = str(bulk_events[item]['row']['details'])
                    details_value = re.sub(r'[\n\r]', ' ', details_value)  # Replace newline and carriage return characters with spaces
                    details_value = details_value.replace('"', '\\"')  # Escape double quotes
                    build_event = build_event + 'details="' + details_value + '",'
                build_event = build_event + "event_type=" + "security" + ","
                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","
                build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","
                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","
                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","
                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","
                build_event = build_event + "type=" + str(bulk_events[item]['row']['violationType']) + ","
                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","
                build_event = build_event + "tenantid=" + str(tenantid) + ","
                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])
                if 'request' in bulk_events[item]['row']:
                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)
                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]
                if 'headers' in bulk_events[item]['row']:
                    referer = re.search(referer_pattern, bulk_events[item]['row']['headers'], re.MULTILINE)
                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]
            elif (bulk_events[item]['row']['targetModule'] == "Attackers Feed") or (
                    bulk_events[item]['row']['targetModule'] == "Geo-Blocking"):
                build_event = "_time=" + str(
                    datetime.datetime.fromtimestamp(int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","
                if 'directory' in bulk_events[item]['row']:
                    build_event = build_event + "directory=" + str(bulk_events[item]['row']['directory']) + ","
                if 'passive' in bulk_events[item]['row']:
                    build_event = build_event + "passive=" + str(bulk_events[item]['row']['passive']) + ","
                if 'protocol' in bulk_events[item]['row']:
                    build_event = build_event + "protocol=" + str(bulk_events[item]['row']['protocol']) + ","
                if 'details' in bulk_events[item]['row']:
                    details_value = str(bulk_events[item]['row']['details'])
                    details_value = re.sub(r'[\n\r]', ' ', details_value)  # Replace newline and carriage return characters with spaces
                    details_value = details_value.replace('"', '\\"')  # Escape double quotes
                    build_event = build_event + 'details="' + details_value + '",'
                build_event = build_event + "event_type=" + "security" + ","
                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","
                build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","
                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","
                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","
                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","
                build_event = build_event + "type=" + str(bulk_events[item]['row']['eventType']) + ","
                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","
                build_event = build_event + "tenantid=" + str(tenantid) + ","
                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])
                if 'request' in bulk_events[item]['row']:
                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)
                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]
                if 'headers' in bulk_events[item]['row']:
                    referer = re.search(referer_pattern, bulk_events[item]['row']['headers'], re.MULTILINE)
                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]
            elif 'violationCategory' in bulk_events[item]['row'] and bulk_events[item]['row']['violationCategory'] == "HTTP RFC Violations":
                build_event = "_time=" + str(
                    datetime.datetime.fromtimestamp(int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","
                build_event = build_event + "event_type=" + "security" + ","
                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","
                if 'uri' in bulk_events[item]['row']:
                    build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","
                if 'directory' in bulk_events[item]['row']:
                    build_event = build_event + "directory=" + str(bulk_events[item]['row']['directory']) + ","
                if 'passive' in bulk_events[item]['row']:
                    build_event = build_event + "passive=" + str(bulk_events[item]['row']['passive']) + ","
                if 'protocol' in bulk_events[item]['row']:
                    build_event = build_event + "protocol=" + str(bulk_events[item]['row']['protocol']) + ","
                if 'details' in bulk_events[item]['row']:
                    details_value = str(bulk_events[item]['row']['details'])
                    details_value = re.sub(r'[\n\r]', ' ', details_value)  # Replace newline and carriage return characters with spaces
                    details_value = details_value.replace('"', '\\"')  # Escape double quotes
                    build_event = build_event + 'details="' + details_value + '",'
                if 'appwallTimeStamp' in bulk_events[item]['row']:
                    build_event = build_event + "appwallTimeStamp=" + str(bulk_events[item]['row']['appwallTimeStamp']) + ","
                build_event = build_event + "dstPort=" + str(bulk_events[item]['row']['destinationPort']) + ","
                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","
                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","
                build_event = build_event + "fqdn=" + str(bulk_events[item]['row']['host']) + ","
                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","
                build_event = build_event + "module=" + str(bulk_events[item]['row']['module']) + ","
                build_event = build_event + "title=" + str(bulk_events[item]['row']['title']) + ","
                build_event = build_event + "application=" + str(bulk_events[item]['row']['webApp']) + ","
                build_event = build_event + "category=" + str(bulk_events[item]['row']['violationCategory']) + ","
                build_event = build_event + "type=" + str(bulk_events[item]['row']['violationType']) + ","
                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","
                build_event = build_event + "tenantid=" + str(tenantid) + ","
                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])
                if 'request' in bulk_events[item]['row']:
                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)
                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]
                    referer = re.search(referer_pattern, bulk_events[item]['row']['request'], re.MULTILINE)
                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]
                    cookie = re.search(r'^Cookie:\s(.+)?\r\n', bulk_events[item]['row']['request'],re.MULTILINE)
                    if cookie:
                        build_event = build_event + ",cookie=" + str(cookie.group(1)).replace('Cookie: ', '')
                    x_rdwr_port = re.search(r'^X-RDWR-PORT:\s(.+)?\r\n', bulk_events[item]['row']['request'],re.MULTILINE)
                    if x_rdwr_port:
                        build_event = build_event + ",x-rdwr-port=" + str(x_rdwr_port.group(1)).replace('X-RDWR-PORT: ','')
                    X_RDWR_PORT_MM_ORIG_FE_PORT = re.search(r'^X-RDWR-PORT-MM-ORIG-FE-PORT:\s(.+)?\r\n',bulk_events[item]['row']['request'], re.MULTILINE)
                    if X_RDWR_PORT_MM_ORIG_FE_PORT:
                        build_event = build_event + ",x-rdwr-port-mm-orig-fe-port=" + str(X_RDWR_PORT_MM_ORIG_FE_PORT.group(1)).replace('X-RDWR-PORT-MM-ORIG-FE-PORT: ', '')
                    X_RDWR_PORT_MM = re.search(r'^X-RDWR-PORT-MM:\s(.+)?\r\n',bulk_events[item]['row']['request'],re.MULTILINE)
                    if X_RDWR_PORT_MM:
                        build_event = build_event + ",x-rdwr-port-mm=" + str(X_RDWR_PORT_MM.group(1)).replace('X-RDWR-PORT-MM: ', '')
            else:
                build_event = "_time=" + str(datetime.datetime.fromtimestamp(int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","
                build_event = build_event + "event_type=" + "security" + ","
                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","
                if 'directory' in bulk_events[item]['row']:
                    build_event = build_event + "directory=" + str(bulk_events[item]['row']['directory']) + ","
                if 'passive' in bulk_events[item]['row']:
                    build_event = build_event + "passive=" + str(bulk_events[item]['row']['passive']) + ","
                if 'protocol' in bulk_events[item]['row']:
                    build_event = build_event + "protocol=" + str(bulk_events[item]['row']['protocol']) + ","
                if 'details' in bulk_events[item]['row']:
                    details_value = str(bulk_events[item]['row']['details'])
                    details_value = re.sub(r'[\n\r]', ' ', details_value)  # Replace newline and carriage return characters with spaces
                    details_value = details_value.replace('"', '\\"')  # Escape double quotes
                    build_event = build_event + 'details="' + details_value + '",'
                if 'appwallTimeStamp' in bulk_events[item]['row']:
                    build_event = build_event + "appwallTimeStamp=" + str(bulk_events[item]['row']['appwallTimeStamp']) + ","
                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","
                build_event = build_event + "dstPort=" + str(bulk_events[item]['row']['destinationPort']) + ","
                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","
                if 'host' in bulk_events[item]['row']:
                    build_event = build_event + "fqdn=" + str(bulk_events[item]['row']['host']) + ","
                if 'uri' in bulk_events[item]['row']:
                    build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","
                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","
                build_event = build_event + "module=" + str(bulk_events[item]['row']['module']) + ","
                build_event = build_event + "title=" + str(bulk_events[item]['row']['title']) + ","
                build_event = build_event + "application=" + str(bulk_events[item]['row']['webApp']) + ","
                build_event = build_event + "category=" + str(bulk_events[item]['row']['violationCategory']) + ","
                build_event = build_event + "type=" + str(bulk_events[item]['row']['violationType']) + ","
                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","
                build_event = build_event + "tenantid=" + str(tenantid) + ","
                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])
                if bulk_events[item]['row']['request']:
                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)
                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]
                    referer = re.search(referer_pattern, bulk_events[item]['row']['request'], re.MULTILINE)
                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]
                    cookie = re.search(r'^Cookie:\s(.+)?\r\n', bulk_events[item]['row']['request'], re.MULTILINE)
                    if cookie:
                        build_event = build_event + ",cookie=" + str(cookie.group(1)).replace('Cookie: ', '')
                    x_rdwr_port = re.search(r'^X-RDWR-PORT:\s(.+)?\r\n', bulk_events[item]['row']['request'],
                                            re.MULTILINE)
                    if x_rdwr_port:
                        build_event = build_event + ",x-rdwr-port=" + str(x_rdwr_port.group(1)).replace('X-RDWR-PORT: ', '')
                    X_RDWR_PORT_MM_ORIG_FE_PORT = re.search(r'^X-RDWR-PORT-MM-ORIG-FE-PORT:\s(.+)?\r\n',bulk_events[item]['row']['request'], re.MULTILINE)
                    if X_RDWR_PORT_MM_ORIG_FE_PORT:
                        build_event = build_event + ",x-rdwr-port-mm-orig-fe-port=" + str(X_RDWR_PORT_MM_ORIG_FE_PORT.group(1)).replace('X-RDWR-PORT-MM-ORIG-FE-PORT: ', '')
                    X_RDWR_PORT_MM = re.search(r'^X-RDWR-PORT-MM:\s(.+)?\r\n', bulk_events[item]['row']['request'],re.MULTILINE)
                    if X_RDWR_PORT_MM:
                        build_event = build_event + ",x-rdwr-port-mm=" + str(X_RDWR_PORT_MM.group(1)).replace('X-RDWR-PORT-MM: ', '')
            event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(),sourcetype=helper.get_sourcetype(), data=build_event)
            ew.write_event(event)
            item += 1
        except:
            logging.error("Error occurred with security events from Cloud AppSec portal : %s\n%s", bulk_events[item]['row'],traceback.format_exc())
            return -1
    return
def format_activity(helper,ew,bulk_activity):
    item = 0
    build_event = ""
    while item < len(bulk_activity['userActivityLogs']):
        build_event = "_time=" + str(datetime.datetime.fromtimestamp(int(bulk_activity['userActivityLogs'][item]['startDate']) / 1000.0)) + ","
        build_event = build_event + "event_type=" + "activity" + ","
        build_event = build_event + "id=" + str(bulk_activity['userActivityLogs'][item]['trackingId']) + ","
        build_event = build_event + "user=" + str(bulk_activity['userActivityLogs'][item]['userEmail']) + ","
        build_event = build_event + "details=" + str(bulk_activity['userActivityLogs'][item]['processTypeText']) + ","
        build_event = build_event + "status=" + str(bulk_activity['userActivityLogs'][item]['status']) + ","
        build_event = build_event + "userIP=" + str(bulk_activity['userActivityLogs'][item]['userIp']) + ","
        build_event = build_event + "country=" + str(bulk_activity['userActivityLogs'][item]['userCountry']) + ","
        build_event = build_event + "activity=" + str(bulk_activity['userActivityLogs'][item]['activityType']) + ","
        build_event = build_event + "user-agent=" + str(bulk_activity['userActivityLogs'][item]['userAgent'])
        event=helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=build_event)
        ew.write_event(event)
        item+=1
    return
def format_ddos_event(helper,ew,bulk_events):
    item = 0
    build_event = ""
    while item < len(bulk_events):
        build_event = "_time=" + str(
            datetime.datetime.fromtimestamp(int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","
        build_event = build_event + "event_type=" + "ddos" + ","
        build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","
        build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['source_address']) + ","
        build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['source_port']) + ","
        build_event = build_event + "dstIP=" + str(bulk_events[item]['row']['destination_address']) + ","
        build_event = build_event + "dstPort=" + str(bulk_events[item]['row']['destination_port']) + ","
        build_event = build_event + "protocol=" + str(bulk_events[item]['row']['protocol']) + ","
        build_event = build_event + "type=" + str(bulk_events[item]['row']['attack_name']) + ","
        build_event = build_event + "category=" + str(bulk_events[item]['row']['category']) + ","
        build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","
        if 'packets' in bulk_events[item]['row']:
            build_event = build_event + "packets=" + str(bulk_events[item]['row']['packet_count']) + ","
        build_event = build_event + "transId=" + str(bulk_events[item]['row']['id'])
        event=helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=build_event)
        ew.write_event(event)
        item += 1
    return
def collect_events(helper, ew):
    stanza=helper.get_input_stanza()
    for key in stanza:
        interval=int(stanza[key]['interval'])
        pass
    app_id=""
    page=1
    credentials={}
    bulk_events={}
    applicationIDs={}
    bulk_activity={}
    type_logs=helper.get_arg('type_of_logs')
    more_pages = False
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
    if ((credentials['proxy_ip'] == "0.0.0.0") ^ (credentials['proxy_port'] == 0)):
        logging.error("Proxy settings need to be reviewed. Either IP or port is left as default")
    elif (type_logs == {}):
        logging.error("Type of logs needs to be reviewed. You didn't select any type.")
    else:
        if ((credentials['proxy_ip'] != "0.0.0.0") and (credentials['proxy_port'] != 0)):
            credentials['use_proxy'] = True
        # Get the session token for the user, using the user and key
        getSessionToken(credentials)
        # Get the autherization token for the user, using the session token
        getAuthorizationToken(credentials)
        # Get the tenantID for the user, using the authorization token
        credentials["TenantID"]=getTenantID(helper,credentials)
        # Retrieve the events list using the authentication token and time filters
        now=int(round(time.time() * 1000))
        past=now-(interval*1000)
        if 'waf_events' in type_logs:
            page=0
            logging.info("WAF events were found!")
            bulk_events=getSecurityEvents(credentials,str(past),str(now),page)
            logging.debug("the number of bulk_events in security events: %s for page: %d", len(bulk_events), page)
            logging.debug("the timestamps in EPOCH (milliseconds). lower: %s , upper: %s", str(past), str(now))
            while(len(bulk_events) != 0):
                format_security_event(helper,ew,bulk_events, credentials["TenantID"])
                page +=1
                #logging.info("more WAF pages were found, current page: %d", page)
                bulk_events=getSecurityEvents(credentials,str(past),str(now),page)
                logging.debug("the number of bulk_events in security events: %s for page: %d", len(bulk_events), page)
        bulk_events.clear()
        if 'ddos_events' in type_logs:
            page = 0
            logging.info("DDoS events were found, current page: %d", page)
            bulk_events = getDDoSEvents(credentials, str(past), str(now), page)
            while(len(bulk_events) != 0):
                format_ddos_event(helper,ew,bulk_events)
                page +=1
                logging.info("more DDoS pages were found, current page: %d", page)
                bulk_events = getDDoSEvents(credentials, str(past), str(now), page)
            bulk_events.clear()
        if 'bot_events' in type_logs:
            applicationIDs["applicationIds"] = getApplicationIDs(credentials)
            bulk_events.clear()
            page=1
            logging.info("Bot events were found, current page: %d", page)
            bulk_events=getBotEvents(credentials, str(past), str(now),applicationIDs,str(page))
            while (bulk_events != 0) and (bulk_events != -1):
                format_bot_event(helper,ew,bulk_events,page)
                logging.info("more Bot pages were found, current page: %d", page)
                page+=1
                bulk_events=getBotEvents(credentials, str(past), str(now),applicationIDs,str(page))
        if 'user_activity' in type_logs:
            bulk_activity = json.loads(getActivity(credentials,str(past),str(now)))
            if (bulk_activity != 0):
                format_activity(helper,ew,bulk_activity)
        logging.info("finished one cycle of events")
        LogOut(credentials)