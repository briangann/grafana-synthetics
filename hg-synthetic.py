#!/usr/bin/env python
"""
Grafana Login Synthetic
"""
import json
import argparse
import time
import sys
import os
import urlparse
import urllib
import uuid
import socket
import re
import requests as req
import uuid
from requests.packages.urllib3.exceptions import InsecureRequestWarning
req.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SyntheticMetric:
    name = ''
    value = 0
    tags = {}

    def __init__(self, name, value, step_number, runner, request_method, info, instance_name, org_id,
                 start_timestamp, end_timestamp, duration_ms,
                 transaction_id, transaction_timestamp, unit,
                 metric_type="gauge"):
      self.name = name
      self.value = value
      self.transaction_timestamp = transaction_timestamp
      self.tags = {}
      self.tags['synthetic_step'] = step_number
      self.tags['runner'] = runner
      self.tags['request_method'] = request_method
      self.tags['info'] = info
      self.tags['instance_name'] = instance_name
      self.tags['org_id'] = org_id
      self.tags['unit'] = unit
      self.tags['mtype'] = metric_type
      #self.tags['start_timestamp'] = start_timestamp
      #self.tags['end_timestamp'] = end_timestamp
      #self.tags['duration_ms'] = duration_ms
      #self.tags['transaction_id'] = transaction_id
      #self.tags['transaction_timestamp'] = transaction_timestamp

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def toGRAPHITE(self):
        tags_flattened = 'step={};'.format(self.tags['synthetic_step'])
        #tags_flattened += 'short_description=Short_Description;'
        tags_flattened += 'runner={};'.format(self.tags['runner'])
        tags_flattened += 'request_method={};'.format(
            self.tags['request_method'])
        tags_flattened += 'info={};'.format(self.tags['info'])
        tags_flattened += 'instance_name={};'.format(
            self.tags['instance_name'])
        tags_flattened += 'org_id={};'.format(self.tags['org_id'])
        tags_flattened += 'mtype={};'.format(self.tags['mtype'])
        tags_flattened += 'unit={}'.format(self.tags['unit'])
        #tags_flattened += 'start_timestamp={};'.format(self.tags['start_timestamp'])
        #tags_flattened += 'end_timestamp={};'.format(self.tags['end_timestamp'])
        #tags_flattened += 'duration_ms={};'.format(self.tags['duration_ms'])
        #tags_flattened += 'transaction_id={};'.format(self.tags['transaction_id'])
        return '{};{} {} {}'.format(self.name, tags_flattened, self.value, self.transaction_timestamp)


def current_milli_time():
    """
    returns current time in milliseconds since epoch
    """
    return int(round(time.time() * 1000))


def current_second_time():
    """
    returns current time in seconds since epoch
    """
    return int(round(time.time()))


def synthetic_get(a_session,
                  runner,
                  info,
                  instance_name,
                  org_id,
                  transaction_timestamp,
                  transaction_id,
                  step_number,
                  target,
                  expected_response_code,
                  cookies=None,
                  headers=None,
                  metric_type='gauge'):
    print 'SYNTHETIC GET - STEP {}: {}'.format(step_number, target)
    metrics = []
    synthetic_result = 0
    start_timestamp = current_milli_time()
    # start synthetic
    resp = a_session.get(
        target, verify=False, allow_redirects=False, cookies=cookies, headers=headers)
    # end of synthetic
    end_timestamp = current_milli_time()
    # check the status code
    if resp.status_code == expected_response_code:
        synthetic_result = 1
    duration_ms = end_timestamp - start_timestamp
    print 'SYNTHETIC GET - STEP {}: {}  DURATION: {}ms'.format(step_number, target, duration_ms)
    # create metrics
    prefix = 'hosted_grafana'
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.result'.format(prefix, step_number),
        synthetic_result,
        '{}.step_{:02}'.format(prefix, step_number),
        runner,
        'GET',
        info,
        instance_name,
        org_id,
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(transaction_id),
        transaction_timestamp,
        'boolean',
        str(metric_type)
          ))

    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.duration'.format(prefix, step_number),
        duration_ms,
        '{}.step_{:02}'.format(prefix, step_number),
        runner,
        'GET',
        info,
        instance_name,
        org_id,
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(transaction_id),
        transaction_timestamp,
        'ms',
        str(metric_type)
      )
    )
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.status_code'.format(prefix, step_number),
        resp.status_code,
        '{}.step_{:02}'.format(prefix, step_number),
        runner,
        'GET',
        info,
        instance_name,
        org_id,
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(transaction_id),
        transaction_timestamp,
        'integer',
        str(metric_type)
      )
    )
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.content_size'.format(prefix, step_number),
        len(resp.content),
        '{}.step_{:02}'.format(prefix, step_number),
        runner,
        'GET',
        info,
        instance_name,
        org_id,
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(transaction_id),
        transaction_timestamp,
        'B',
        str(metric_type)
      )
    )
    # return metrics, result, and the http response object
    return metrics, synthetic_result, resp


def post_login(config, data):
    """
    performs target request using cookie
    """
    #data = {'login': config['username'], 'password': config['password'] }
    # convert to a string
    #print json.dumps(data)
    headers = {
      'Content-Type': 'application/json;charset=UTF-8',
      'Referer': config['referer'],
      'Accept': 'application/json, text/plain, */*',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'en-US,en;q=0.9',
      'X-Request-ID': config['x_request_id'],
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'
    }
    resp = config['a_session'].post(
        config['target'],
        verify=False,
        headers=headers,
        cookies=config['cookies'],
        data=json.dumps(data),
        allow_redirects=False)
    #print resp.request.headers
    return resp


def synthetic_post(config, step_number, expected_response_code, data):
    metrics = []
    synthetic_result = 0
    start_timestamp = current_milli_time()
    # start synthetic
    resp = post_login(config, data)
    # end of synthetic
    #print resp
    #print resp.status_code
    #print "############"
    end_timestamp = current_milli_time()
    # check the status code
    if resp.status_code == expected_response_code:
        synthetic_result = 1
    duration_ms = end_timestamp - start_timestamp
    print 'SYNTHETIC POST - STEP {}: {} DURATION: {}ms'.format(step_number, config['target'], duration_ms)

    # create metrics
    prefix = 'hosted_grafana'
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.result'.format(prefix, step_number),
        synthetic_result,
        '{}.step_{:02}'.format(prefix, step_number),
        config['runner'],
        'POST',
        config['info'],
        config['instance'],
        config['org_id'],
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(config['transaction_id']),
        config['transaction_timestamp'],
        'boolean',
        'gauge'
      )
    )
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.duration'.format(prefix, step_number),
        duration_ms,
        '{}.step_{:02}'.format(prefix, step_number),
        config['runner'],
        'POST',
        config['info'],
        config['instance'],
        config['org_id'],
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(config['transaction_id']),
        config['transaction_timestamp'],
        'ms',
        'gauge'
      )
    )
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.status_code'.format(prefix, step_number),
        resp.status_code,
        '{}.step_{:02}'.format(prefix, step_number),
        config['runner'],
        'POST',
        config['info'],
        config['instance'],
        config['org_id'],
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(config['transaction_id']),
        config['transaction_timestamp'],
        'integer',
        'gauge'
      )
    )
    metrics.append(
      SyntheticMetric(
        '{}.step_{:02}.content_size'.format(prefix, step_number),
        len(resp.content),
        '{}.step_{:02}'.format(prefix, step_number),
        config['runner'],
        'POST',
        config['info'],
        config['instance'],
        config['org_id'],
        str(start_timestamp),
        str(end_timestamp),
        duration_ms,
        str(config['transaction_id']),
        config['transaction_timestamp'],
        'B',
        'gauge'
      )
    )
    return metrics, synthetic_result, resp


def step1(config):
    '''
    Try connecting to the hosted grafana instance
    '''
    print 'Step 1: Target: {}'.format(config['target'])
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      1,
      config['target'],
      302,
      None,
      None,
      metric_type='gauge')
    return synthetic_metrics, synthetic_result, response


def step2(config, step1_response):
    '''
    Follow redirect to /login
    '''
    parsed = urlparse.urlparse(step1_response.headers['Location'])
    target = config['target'] + parsed.path
    print 'Step 2: Target: {}'.format(target)
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      2,
      target,
      200,
      config['cookies'],
      None,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response


def step3(config):
    '''
    Contact instance/grafana.net/login
    '''
    print 'Step 3: Target: {}'.format(config['target'])
    headers = {
      'Host': '{}.grafana.net'.format(config['instance']),
      "Referer": 'https://{}.grafana.net/login'.format(config['instance']),
      'Accept': 'text/html,application',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'en-US,en;q=0.5',
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'
    }
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      3,
      config['target'],
      302,
      config['cookies'],
      headers,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response


def step4(config, step3_response):
    headers = {
      'Host': '{}.grafana.net'.format(config['instance']),
      "Referer": 'https://{}.grafana.net/login'.format(config['instance']),
      'Accept': 'text/html,application',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'en-US,en;q=0.5',
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'
    }
    regex = ';state=(?P<STATE>.*)\"'
    state_hash = ''
    try:
        m = re.search(regex, step3_response.text)
        #print m.group('STATE')
        state_hash = m.group('STATE')
    except:
      print "state not returned in step3, ERROR!"
    '''
    response contains
    <a href="https://grafana.com/oauth2/authorize?access_type=online&amp;client_id=f1383f63a6a46680e384&amp;redirect_uri=https%3A%2F%2Fbkgann3.grafana.net%2Flogin%2Fgrafana_com&amp;response_type=code&amp;scope=user%3Aemail&amp;state=nogNCBRynxOi1cKyj5vld5jUfogbTWqV5n45NAINgpQ%3D">Found</a>.
    '''
    # get the client_id for use later
    regex = 'client_id=(?P<CLIENTID>.*)&amp;redirect_uri'
    m = re.search(regex, step3_response.text)
    client_id = m.group('CLIENTID')
    #print "CLIENT_ID = {}".format(client_id)
    # parse response text get the next url to hit
    regex = 'a href=\"(?P<REDIRECT>([^"]|"")*)'
    m = re.search(regex, step3_response.text)
    #print m.group('REDIRECT')
    # hit the redirect
    target = m.group('REDIRECT')
    print 'Step 4: Target: {}'.format(target)

    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      4,
      target,
      302,
      config['cookies'],
      headers,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response, client_id, state_hash, target


def step5(config, step4_response):
    headers = {
      'Host': '{}.grafana.net'.format(config['instance']),
      "Referer": 'https://{}.grafana.net/login'.format(config['instance']),
      'Accept': 'text/html,application',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'en-US,en;q=0.5',
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'
    }
    # parse response text get the next url to hit
    regex = 'a href=\"(?P<REDIRECT>([^"]|"")*)'
    m = re.search(regex, step4_response.text)
    # this will give us a 200
    target = "https://grafana.com{}".format(m.group('REDIRECT'))
    print 'Step 5: Target: {}'.format(target)

    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      5,
      target,
      200,
      config['cookies'],
      headers,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response


def step6(config):
    config['target'] = "https://grafana.com/api/login"
    print 'Step 6: Target: {}'.format(config['target'])
    data = {
      'login': config['username'],
      'password': config['password']
    }
    synthetic_metrics, synthetic_result, response = synthetic_post(
        config, 6, 200, data)
    return synthetic_metrics, synthetic_result, response


def step7(config, cookies, client_id):
    '''
    Get OAuth2 Clients
    '''
    config['target'] = 'https://grafana.com/api/oauth2/clients/{}'.format(
        client_id)
    print 'Step 7: Target: {}'.format(config['target'])
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      7,
      config['target'],
      200,
      cookies,
      None,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response


def step8(config, cookies, client_id):
    '''
    Get OAuth2 Grants
    '''
    config['target'] = 'https://grafana.com/api/oauth2/grants?clientId={}'.format(
        client_id)
    print 'Step 8: Target: {}'.format(config['target'])
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      8,
      config['target'],
      200,
      cookies,
      None,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response


def step9(config):
    '''
    The POST will respond with json including a code we need
    {
      "id":278982,
      "redirectUri":"https://bkgann3.grafana.net/login/grafana_com",
      "clientId":"f1383f63a6a46680e384",
      "orgId":127614,
      "userId":109701,
      "grantId":62424,
      "createdAt":"2018-09-15T15:16:32.000Z",
      "updatedAt":null,
      "expiresAt":"2018-09-15T15:21:32.000Z",
      "code":"f343ddd8dc9918645978882e7b1730a116b1ea00",
      "links":[{"rel":"self","href":"/oauth2/codes/278982"}]}
    '''
    data = {
      'client_id': config['client_id'],
      'redirect_uri': config['redirect_uri'],
      'scope': config['scope']
    }
    print 'Step 9: Target: {}'.format(config['target'])

    synthetic_metrics, synthetic_result, response = synthetic_post(
        config, 9, 200, data)
    return synthetic_metrics, synthetic_result, response


def step10(config, cookies, oauth_token):
    '''
    Get OAuth2 Grants
    '''
    config['target'] = '{}?code={}&state={}'.format(
      oauth_token['redirectUri'],
      oauth_token['code'],
      config['state_hash']
    )
    print 'Step 10: Target: {}'.format(config['target'])
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      10,
      config['target'],
      302,
      cookies,
      None,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response


def step11(config, cookies):
    print 'Step 10: Target: {}'.format(config['target'])
    synthetic_metrics, synthetic_result, response = synthetic_get(
      config['a_session'],
      config['runner'],
      config['info'],
      config['instance'],
      config['org_id'],
      config['transaction_timestamp'],
      config['transaction_id'],
      11,
      config['target'],
      200,
      cookies,
      None,
      metric_type='gauge'
    )
    return synthetic_metrics, synthetic_result, response

    '''
    last_cookies = resp_redirected.cookies
    target = xyz['redirectUri']
    target_parsed = urlparse.urlparse(target)
    target = '{}://{}'.format(target_parsed.scheme, target_parsed.netloc)
    last_step = a_session.get(target, cookies=last_cookies, verify=False, allow_redirects=False)
    print last_step
    # this will be a 200
    print last_step.status_code
    print last_step.headers
    #print last_step.content
    # parse content to locate user: {"isSignedIn":true,
    regex = '{\"isSignedIn\":(?P<SIGNEDIN>.*)\,\"id\":'
    m = re.search(regex, last_step.text)
    print m.group('SIGNEDIN')
    if m.group('SIGNEDIN') == 'true':
        print "YES!"
    else:
        print "ERROR"
    '''


def perform_synthetic(instance, org_id, runner, username, password):
    all_metrics = []

    a_session = req.Session()
    transaction_id = str(uuid.uuid4())
    transaction_timestamp = current_second_time()
    info = 'HostedGrafanaSynthetic'
    # STEP 1
    target = 'https://{}.grafana.net'.format(instance)
    config = {
      'a_session': a_session,
      'instance': instance,
      'org_id': org_id,
      'transaction_id': transaction_id,
      'transaction_timestamp': transaction_timestamp,
      'info': info,
      'target': target,
      'runner': runner,
      'cookies': None
    }
    synthetic_metrics, synthetic_result, step1_response = step1(config)
    all_metrics.extend(synthetic_metrics)

    # STEP 2
    config['cookies'] = step1_response.cookies
    cookies = step1_response.cookies
    synthetic_metrics, synthetic_result, step1_response = step2(
        config, step1_response)
    all_metrics.extend(synthetic_metrics)

    # STEP 3: login with grafana.com, this will be a redirect
    # https://<instancename>.grafana.net/login/grafana_com
    config['target'] = 'https://{}.grafana.net/login/grafana_com'.format(
        instance)
    synthetic_metrics, synthetic_result, step3_response = step3(config)
    all_metrics.extend(synthetic_metrics)

    # STEP 4
    synthetic_metrics, synthetic_result, step4_response, client_id, state_hash, target = step4(
        config, step3_response)
    all_metrics.extend(synthetic_metrics)
    # used in step 10
    config['state_hash'] = state_hash

    # STEP 5
    synthetic_metrics, synthetic_result, step5_response = step5(
        config, step4_response)
    all_metrics.extend(synthetic_metrics)

    # STEP 6 - POST to authenticate
    target = "https://grafana.com/api/login"
    # also need to make a request id and use it from here forward
    # X-Request-ID: 348adcdb-78b3-43ed-0330-cfe7c730d01
    config['x_request_id'] = transaction_id
    config['username'] = username
    config['password'] = password
    config['referer'] = ''
    synthetic_metrics, synthetic_result, step6_response = step6(config)
    all_metrics.extend(synthetic_metrics)

    #print step6_response.status_code
    #print step6_response.text
    login_cookies = step6_response.cookies
    #print login_cookies

    # STEP 7: Get clients
    # GET oauth2 client id https://grafana.com/api/oauth2/clients/f63a6a46680e384

    synthetic_metrics, synthetic_result, step7_response = step7(
        config, login_cookies, client_id)
    all_metrics.extend(synthetic_metrics)
    #print step7_response.status_code
    #print step7_response.text
    oauth2_clients = json.loads(step7_response.text)

    # STEP 8: Get grants
    # GET grants https://grafana.com/api/oauth2/grants?clientId=<CLIENTID>

    synthetic_metrics, synthetic_result, step8_response = step8(
        config, login_cookies, client_id)
    all_metrics.extend(synthetic_metrics)
    #print step8_response.status_code
    #print step8_response.text
    oauth2_grants = json.loads(step8_response.text)

    # STEP 9: Get OAUTH2 token
    # POST to https://grafana.com/api/oauth2/authorize
    # {
    #   "client_id":"<CLIENTID>",
    #   "redirect_uri":"https://<INSTANCE>.grafana.net/login/grafana_com",
    #   "scope":"user:email"
    # }
    print(oauth2_clients)
    config['redirect_uri'] = oauth2_clients['redirectUri']
    config['scope'] = oauth2_grants['items'][0]['scope']
    config['target'] = 'https://grafana.com/api/oauth2/authorize'
    config['client_id'] = client_id
    synthetic_metrics, synthetic_result, step9_response = step9(config)
    all_metrics.extend(synthetic_metrics)
    #print step9_response.status_code
    #print step9_response.text

    # STEP 10: Use the code to login to the HG instance
    # GET https://bkgann3.grafana.net/login/grafana_com?code=19e5a25888fb3ad9939df8ea9224ada3908914c8&state=-jFBAiR9O7NH5sL3jC1sq5M1XCXb8yEPbgmXnFl2D3k%3D
    # which will respond with a 302 redirect, and new cookies
    # get the redirectUri and code
    oauth_token = json.loads(step9_response.text)
    #print oauth_token['redirectUri']
    #print oauth_token['code']
    config['target'] = '{}?code={}&state={}'.format(
        oauth_token['redirectUri'], oauth_token['code'], state_hash)
    synthetic_metrics, synthetic_result, step10_response = step10(
        config, login_cookies, oauth_token)
    #print synthetic_metrics
    all_metrics.extend(synthetic_metrics)
    #print step10_response.status_code
    #print step10_response.text

    # STEP 11
    # last step is to hit the site again with the new cookies, and get a 200 response
    # GET https://bkgann3.grafana.net/
    # parse the response text for isSignedIn: true
    '''
     window.grafanaBootData = {
      user: {"isSignedIn":true,"id":6,"login":"bkgann","email":"brian@grafana.com","name":"Brian Gann","lightTheme":false,"orgCount":1,"orgId":1,"orgName":"Main Org.","orgRole":"Admin","isGrafanaAdmin":false,"gravatarUrl":"/avatar/a544def6744ce7cb4d0edc23c4c8b15d","timezone":"browser","locale":"en-US","helpFlags1":0,"hasEditPermissionInFolders":true},
      settings: {"alertingEnabled":true,"allowOrgCreate":false,"appSubUrl":"","authProxyEnabled":false,"buildInfo":{"buildstamp":1536330916,"commit":"0bbac5c","env":"production","hasUpdate":false,"latestVersion":"5.2.4","version":"5.2.4"},"datasources":{"-- Grafana --":{"meta":{"type":"datasource","name":"-- Grafana --","id":"grafana","info":{"author":{"name":"","url":""},"description":"","links":null,"logos":{"small":"public/img/icn-datasource.svg","large":"public/img/icn-datasource.svg"},"screenshots":null,"version":"","updated":""},"dependencies":{"grafanaVersion":"*","plugins":[]},"includes":null,"module":"app/plugins/datasource/grafana/module","baseUrl":"public/app/plugins/datasource/grafana","annotations":true,"metrics":true,"alerting":false,"builtIn":true,"routes":null},"name":"-- Grafana --","type":"datasource"},"-- Mixed --":{"meta":{"type":"datasource","name":"-- Mixed --","id":"mixed","info":{"author":{"name":"","url":""},"description":"","links":null,"logos":{"small":"public/img/icn-datasource.svg","large":"public/img/icn-datasource.svg"},"screenshots":null,"version":"","updated":""},"dependencies":{"grafanaVersion":"*","plugins":[]},"includes":null,"module":"app/plugins/datasource/mixed/module","baseUrl":"public/app/plugins/datasource/mixed","annotations":false,"metrics":true,"alerting":false,"queryOptions":{"minInterval":true},"builtIn":true,"mixed":true,"routes":null},"name":"-- Mixed --","type":"datasource"}},"defaultDatasource":"-- Grafana --","disableLoginForm":true,"exploreEnabled":false,"externalUserMngInfo":"Users are managed via [grafana.com](https://grafana.com). The table below shows users who have logged in at least once. To remove a user you also need to remove them from your [grafana.com](https://grafana.com) org.","externalUserMngLinkName":"Manage users on grafana.com","externalUserMngLinkUrl":"https://grafana.com","googleAnalyticsId":"UA-58328364-6","ldapEnabled":false,"panels":{"alertlist":{"baseUrl":"public/app/plugins/panel/alertlist","hideFromList":false,"id":"alertlist","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"Shows list of alerts and their current status","links":null,"logos":{"small":"public/app/plugins/panel/alertlist/img/icn-singlestat-panel.svg","large":"public/app/plugins/panel/alertlist/img/icn-singlestat-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/alertlist/module","name":"Alert List","sort":6},"dashlist":{"baseUrl":"public/app/plugins/panel/dashlist","hideFromList":false,"id":"dashlist","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"List of dynamic links to other dashboards","links":null,"logos":{"small":"public/app/plugins/panel/dashlist/img/icn-dashlist-panel.svg","large":"public/app/plugins/panel/dashlist/img/icn-dashlist-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/dashlist/module","name":"Dashboard list","sort":7},"gettingstarted":{"baseUrl":"public/app/plugins/panel/gettingstarted","hideFromList":true,"id":"gettingstarted","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"","links":null,"logos":{"small":"public/app/plugins/panel/gettingstarted/img/icn-dashlist-panel.svg","large":"public/app/plugins/panel/gettingstarted/img/icn-dashlist-panel.svg"},"screenshots":null,"version":"","updated":""},"module":"app/plugins/panel/gettingstarted/module","name":"Getting Started","sort":100},"grafana-worldmap-panel":{"baseUrl":"public/plugins/raintank-worldping-app","hideFromList":false,"id":"grafana-worldmap-panel","info":{"author":{"name":"Raintank Inc.","url":"http://raintank.io"},"description":"World Map panel for grafana. Displays time series data or geohash data from Elasticsearch overlaid on a world map.","links":[{"name":"Project site","url":"https://github.com/grafana/worldmap-panel"},{"name":"MIT License","url":"https://github.com/grafana/worldmap-panel/blob/master/LICENSE"}],"logos":{"small":"public/plugins/grafana-worldmap-panel/src/images/worldmap_logo.svg","large":"public/plugins/grafana-worldmap-panel/src/images/worldmap_logo.svg"},"screenshots":[{"path":"public/plugins/grafana-worldmap-panel/src/images/worldmap-world.png","name":"World"},{"path":"public/plugins/grafana-worldmap-panel/src/images/worldmap-usa.png","name":"USA"},{"path":"public/plugins/grafana-worldmap-panel/src/images/worldmap-light-theme.png","name":"Light Theme"}],"version":"0.0.16","updated":"2016-10-20"},"module":"plugins/raintank-worldping-app/grafana-worldmap-panel/module","name":"Worldmap Panel","sort":100},"graph":{"baseUrl":"public/app/plugins/panel/graph","hideFromList":false,"id":"graph","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"Graph Panel for Grafana","links":null,"logos":{"small":"public/app/plugins/panel/graph/img/icn-graph-panel.svg","large":"public/app/plugins/panel/graph/img/icn-graph-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/graph/module","name":"Graph","sort":1},"heatmap":{"baseUrl":"public/app/plugins/panel/heatmap","hideFromList":false,"id":"heatmap","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"Heatmap Panel for Grafana","links":[{"name":"Brendan Gregg - Heatmaps","url":"http://www.brendangregg.com/heatmaps.html"},{"name":"Brendan Gregg - Latency Heatmaps","url":" http://www.brendangregg.com/HeatMaps/latency.html"}],"logos":{"small":"public/app/plugins/panel/heatmap/img/icn-heatmap-panel.svg","large":"public/app/plugins/panel/heatmap/img/icn-heatmap-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/heatmap/module","name":"Heatmap","sort":5},"pluginlist":{"baseUrl":"public/app/plugins/panel/pluginlist","hideFromList":false,"id":"pluginlist","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"Plugin List for Grafana","links":null,"logos":{"small":"public/app/plugins/panel/pluginlist/img/icn-dashlist-panel.svg","large":"public/app/plugins/panel/pluginlist/img/icn-dashlist-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/pluginlist/module","name":"Plugin list","sort":100},"singlestat":{"baseUrl":"public/app/plugins/panel/singlestat","hideFromList":false,"id":"singlestat","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"Singlestat Panel for Grafana","links":null,"logos":{"small":"public/app/plugins/panel/singlestat/img/icn-singlestat-panel.svg","large":"public/app/plugins/panel/singlestat/img/icn-singlestat-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/singlestat/module","name":"Singlestat","sort":2},"table":{"baseUrl":"public/app/plugins/panel/table","hideFromList":false,"id":"table","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"Table Panel for Grafana","links":null,"logos":{"small":"public/app/plugins/panel/table/img/icn-table-panel.svg","large":"public/app/plugins/panel/table/img/icn-table-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/table/module","name":"Table","sort":3},"text":{"baseUrl":"public/app/plugins/panel/text","hideFromList":false,"id":"text","info":{"author":{"name":"Grafana Project","url":"https://grafana.com"},"description":"","links":null,"logos":{"small":"public/app/plugins/panel/text/img/icn-text-panel.svg","large":"public/app/plugins/panel/text/img/icn-text-panel.svg"},"screenshots":null,"version":"5.0.0","updated":""},"module":"app/plugins/panel/text/module","name":"Text","sort":4},"worldping-cta":{"baseUrl":"public/plugins/raintank-worldping-app","hideFromList":false,"id":"worldping-cta","info":{"author":{"name":"","url":""},"description":"","links":null,"logos":{"small":"public/img/icn-panel.svg","large":"public/img/icn-panel.svg"},"screenshots":null,"version":"","updated":""},"module":"plugins/raintank-worldping-app/panels/call-to-action/module","name":"worldPing CTA","sort":100},"worldping-endpoint-list":{"baseUrl":"public/plugins/raintank-worldping-app","hideFromList":false,"id":"worldping-endpoint-list","info":{"author":{"name":"","url":""},"description":"","links":null,"logos":{"small":"public/img/icn-panel.svg","large":"public/img/icn-panel.svg"},"screenshots":null,"version":"","updated":""},"module":"plugins/raintank-worldping-app/panels/endpoint-list/module","name":"worldPing Endpoint List","sort":100},"worldping-endpoint-nav":{"baseUrl":"public/plugins/raintank-worldping-app","hideFromList":false,"id":"worldping-endpoint-nav","info":{"author":{"name":"","url":""},"description":"","links":null,"logos":{"small":"public/img/icn-panel.svg","large":"public/img/icn-panel.svg"},"screenshots":null,"version":"","updated":""},"module":"plugins/raintank-worldping-app/panels/nav-panel/module","name":"worldPing Endpoint Nav","sort":100}}},
      navTree: [{"id":"create","text":"Create","icon":"fa fa-fw fa-plus","url":"/dashboard/new","children":[{"text":"Dashboard","icon":"gicon gicon-dashboard-new","url":"/dashboard/new"},{"id":"folder","text":"Folder","subTitle":"Create a new folder to organize your dashboards","icon":"gicon gicon-folder-new","url":"/dashboards/folder/new"},{"id":"import","text":"Import","subTitle":"Import dashboard from file or Grafana.com","icon":"gicon gicon-dashboard-import","url":"/dashboard/import"}]},{"id":"dashboards","text":"Dashboards","subTitle":"Manage dashboards \u0026 folders","icon":"gicon gicon-dashboard","url":"/","children":[{"id":"home","text":"Home","icon":"gicon gicon-home","url":"/","hideFromTabs":true},{"id":"divider","text":"Divider","divider":true,"hideFromTabs":true},{"id":"manage-dashboards","text":"Manage","icon":"gicon gicon-manage","url":"/dashboards"},{"id":"playlists","text":"Playlists","icon":"gicon gicon-playlists","url":"/playlists"},{"id":"snapshots","text":"Snapshots","icon":"gicon gicon-snapshots","url":"/dashboard/snapshots"}]},{"id":"profile","text":"Brian Gann","subTitle":"bkgann","img":"/avatar/a544def6744ce7cb4d0edc23c4c8b15d","url":"/profile","hideFromMenu":true,"children":[{"id":"profile-settings","text":"Preferences","icon":"gicon gicon-preferences","url":"/profile"},{"id":"change-password","text":"Change Password","icon":"fa fa-fw fa-lock","url":"/profile/password","hideFromMenu":true},{"id":"sign-out","text":"Sign out","icon":"fa fa-fw fa-sign-out","url":"/logout","target":"_self"}]},{"id":"alerting","text":"Alerting","subTitle":"Alert rules \u0026 notifications","icon":"gicon gicon-alert","url":"/alerting/list","children":[{"id":"alert-list","text":"Alert Rules","icon":"gicon gicon-alert-rules","url":"/alerting/list"},{"id":"channels","text":"Notification channels","icon":"gicon gicon-alert-notification-channel","url":"/alerting/notifications"}]},{"id":"cfg","text":"Configuration","subTitle":"Organization: Main Org.","icon":"gicon gicon-cog","url":"/datasources","children":[{"id":"datasources","text":"Data Sources","description":"Add and configure data sources","icon":"gicon gicon-datasources","url":"/datasources"},{"id":"users","text":"Users","description":"Manage org members","icon":"gicon gicon-user","url":"/org/users"},{"id":"teams","text":"Teams","description":"Manage org groups","icon":"gicon gicon-team","url":"/org/teams"},{"id":"plugins","text":"Plugins","description":"View and configure plugins","icon":"gicon gicon-plugins","url":"/plugins"},{"id":"org-settings","text":"Preferences","description":"Organization preferences","icon":"gicon gicon-preferences","url":"/org"},{"id":"apikeys","text":"API Keys","description":"Create \u0026 manage API keys","icon":"gicon gicon-apikeys","url":"/org/apikeys"}]},{"id":"help","text":"Help","subTitle":"Grafana v5.2.4 (0bbac5c)","icon":"gicon gicon-question","url":"#","hideFromMenu":true,"children":[{"text":"Keyboard shortcuts","icon":"fa fa-fw fa-keyboard-o","url":"/shortcuts","target":"_self"},{"text":"Community site","icon":"fa fa-fw fa-comment","url":"http://community.grafana.com","target":"_blank"},{"text":"Documentation","icon":"fa fa-fw fa-file","url":"http://docs.grafana.org","target":"_blank"}]}]
    };
    '''
    final_cookies = step10_response.cookies
    target = oauth_token['redirectUri']
    target_parsed = urlparse.urlparse(target)
    #target = urlparse.urlparse(target).netloc
    target = '{}://{}'.format(target_parsed.scheme, target_parsed.netloc)
    #print target
    #print 'target = {}'.format(target)
    config['target'] = target
    synthetic_metrics, synthetic_result, step11_response = step11(
        config, final_cookies)
    all_metrics.extend(synthetic_metrics)
    #print step11_response.status_code
    #print step11_response.text
    # parse content to locate user: {"isSignedIn":true,
    regex = '{\"isSignedIn\":(?P<SIGNEDIN>.*)\,\"id\":'
    m = re.search(regex, step11_response.text)
    #print m.group('SIGNEDIN')
    if m.group('SIGNEDIN') == 'true':
        print "YES!"
    else:
        print "ERROR"

    # Create SUMMARY Metrics
    return all_metrics


def show_metrics(metrics):
    print "Show Metrics"
    for i in range(len(metrics)):
      a_metric = metrics[i]
      #print a_metric.toJSON()
      print a_metric.toGRAPHITE()


def publish_to_graphite_http(url, metrics):
    print("Url: "+url)
    publish_session = req.Session()
    for i in range(len(metrics)):
      a_metric = metrics[i]
      r = publish_session.post(
          url,
          data=a_metric.toGRAPHITE(),
          headers={'Content-Type': 'application/octet-stream'}
      )
      #print(r.status_code, r.reason)
    publish_session.close


def publish_to_graphite_crng(hostname, port_number, metrics):
    print 'publish to graphite: {}:{}'.format(hostname, port_number)
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((hostname, int(port_number)))
    for i in range(len(metrics)):
      a_metric = metrics[i]
      r = clientsocket.send(a_metric.toGRAPHITE() + '\n')
      #print r
    clientsocket.close


def publish_metrics(metrics, hostname, port_number, output_type='graphite',):
    print "Publishing Metrics"
    publish_to_graphite_crng(hostname, port_number, metrics)


def main():
    """
    run script
    """
    parser = argparse.ArgumentParser(
        description='Check Hosted Grafana Login Process.')
    parser.add_argument('-i', '--instance', help='hosted grafana instance name',
                        action='store', dest="instance")
    parser.add_argument('-o', '--orgid', help='hosted grafana orgid',
                        action='store', dest="org_id")
    parser.add_argument('-u', '--user', help='OAuth2 User',
                        action='store', dest="username")
    parser.add_argument('-p', '--password', help='OAuth2 Password',
                        action='store', dest="password")

    args = parser.parse_args()
    instance = args.instance
    org_id = args.org_id
    username = args.username
    password = args.password
    runner = socket.getfqdn()

    if 'HTTPS_PROXY' in os.environ:
        del os.environ['HTTPS_PROXY']
    if 'HTTP_PROXY' in os.environ:
        del os.environ['HTTP_PROXY']
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']
    if 'http_proxy' in os.environ:
        del os.environ['http_proxy']

    all_metrics = perform_synthetic(
        instance, org_id, runner, username, password)
    show_metrics(all_metrics)
    publish_metrics(all_metrics, hostname='127.0.0.1', port_number='9003')
    return 0


if __name__ == "__main__":
    EXIT_CODE = main()
    sys.exit(EXIT_CODE)
