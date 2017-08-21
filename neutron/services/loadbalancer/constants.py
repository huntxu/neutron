# Copyright 2013 Mirantis, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'

PROTOCOL_TCP = 'TCP'
PROTOCOL_HTTP = 'HTTP'
PROTOCOL_HTTPS = 'HTTPS'

HEALTH_MONITOR_PING = 'PING'
HEALTH_MONITOR_TCP = 'TCP'
HEALTH_MONITOR_HTTP = 'HTTP'
HEALTH_MONITOR_HTTPS = 'HTTPS'

HTTP_METHOD_GET = 'GET'
HTTP_METHOD_HEAD = 'HEAD'
HTTP_METHOD_POST = 'POST'
HTTP_METHOD_PUT = 'PUT'
HTTP_METHOD_DELETE = 'DELETE'
HTTP_METHOD_TRACE = 'TRACE'
HTTP_METHOD_OPTIONS = 'OPTIONS'
HTTP_METHOD_CONNECT = 'CONNECT'
HTTP_METHOD_PATCH = 'PATCH'

SUPPORTED_HTTP_METHODS = (HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST,
                          HTTP_METHOD_PUT, HTTP_METHOD_DELETE,
                          HTTP_METHOD_TRACE, HTTP_METHOD_OPTIONS,
                          HTTP_METHOD_CONNECT, HTTP_METHOD_PATCH)

# URL path regex according to RFC 3986
# Format: path = "/" *( "/" segment )
#         segment       = *pchar
#         pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
#         unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
#         pct-encoded   = "%" HEXDIG HEXDIG
#         sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
#                         / "*" / "+" / "," / ";" / "="
#         query = *( pchar / "/" / "?" )
#         fragment = *( pchar / "/" / "?" )
#
PCHAR = "[a-zA-Z0-9-._~!$&\'()*+,;=:@]|(%[a-fA-F0-9]{2})"
SUPPORTED_URL_PATH = (
        "^(/(%s)*)+(\?((%s)|[/\?])*)?(#((%s)|[/\?])*)?$" % (
            PCHAR, PCHAR, PCHAR
        ))

SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'

STATS_ACTIVE_CONNECTIONS = 'active_connections'
STATS_MAX_CONNECTIONS = 'max_connections'
STATS_TOTAL_CONNECTIONS = 'total_connections'
STATS_CURRENT_SESSIONS = 'current_sessions'
STATS_MAX_SESSIONS = 'max_sessions'
STATS_TOTAL_SESSIONS = 'total_sessions'
STATS_IN_BYTES = 'bytes_in'
STATS_OUT_BYTES = 'bytes_out'
STATS_CONNECTION_ERRORS = 'connection_errors'
STATS_RESPONSE_ERRORS = 'response_errors'
STATS_STATUS = 'status'
STATS_HEALTH = 'health'
STATS_FAILED_CHECKS = 'failed_checks'
