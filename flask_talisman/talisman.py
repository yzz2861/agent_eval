# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re
from collections import OrderedDict

import flask
from six import iteritems, string_types


DENY = 'DENY'
SAMEORIGIN = 'SAMEORIGIN'
ALLOW_FROM = 'ALLOW-FROM'
ONE_YEAR_IN_SECS = 31556926

DEFAULT_REFERRER_POLICY = 'strict-origin-when-cross-origin'

DEFAULT_CSP_POLICY = {
    'default-src': '\'self\'',
}

GOOGLE_CSP_POLICY = {
    # Fonts from fonts.google.com
    'font-src': '\'self\' themes.googleusercontent.com *.gstatic.com',
    # <iframe> based embedding for Maps and Youtube.
    'frame-src': '\'self\' www.google.com www.youtube.com',
    # Assorted Google-hosted Libraries/APIs.
    'script-src': '\'self\' ajax.googleapis.com *.googleanalytics.com '
                  '*.google-analytics.com',
    # Used by generated code from http://www.google.com/fonts
    'style-src': '\'self\' ajax.googleapis.com fonts.googleapis.com '
                 '*.gstatic.com',
    'default-src': '\'self\' *.gstatic.com',
}

DEFAULT_FEATURE_POLICY = {
}

NONCE_LENGTH = 16

_CSP_RO_HEADER = 'Content-Security-Policy-Report-Only'
_CSP_HEADER = 'Content-Security-Policy'
_REPORTING_ENDPOINTS_HEADER = 'Reporting-Endpoints'

# RFC 7230 token syntax.  Reporting API endpoint group names are tokens.
_REPORT_TO_TOKEN_RE = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

_CSP_CONFIG_KEYS = frozenset((
    'directives', 'policy', 'report_uri', 'report_to',
    'report_to_endpoint', 'reporting_endpoints', 'nonce_in',
))


class Talisman(object):
    """
    Talisman is a Flask extension for HTTP security headers.
    """

    def __init__(self, app=None, **kwargs):
        if app is not None:
            self.init_app(app, **kwargs)

    def init_app(
            self,
            app,
            feature_policy=DEFAULT_FEATURE_POLICY,
            force_https=True,
            force_https_permanent=False,
            force_file_save=False,
            frame_options=SAMEORIGIN,
            frame_options_allow_from=None,
            strict_transport_security=True,
            strict_transport_security_preload=False,
            strict_transport_security_max_age=ONE_YEAR_IN_SECS,
            strict_transport_security_include_subdomains=True,
            content_security_policy=DEFAULT_CSP_POLICY,
            content_security_policy_report_uri=None,
            content_security_policy_report_only=False,
            content_security_policy_nonce_in=None,
            referrer_policy=DEFAULT_REFERRER_POLICY,
            session_cookie_secure=True,
            session_cookie_http_only=True,
            content_security_policy_enforce=None,
            content_security_policy_report_only_policy=None,
            content_security_policy_report_to=None,
            content_security_policy_report_to_group=None,
            content_security_policy_report_to_endpoint=None,
            content_security_policy_report_to_uri=None,
            content_security_policy_reporting_endpoints=None,
            content_security_policy_enforce_report_uri=None,
            content_security_policy_enforce_report_to=None,
            content_security_policy_enforce_report_to_endpoint=None,
            content_security_policy_report_only_report_uri=None,
            content_security_policy_report_only_report_to=None,
            content_security_policy_report_only_report_to_endpoint=None,
            content_security_policy_report_only_nonce_in=None):
        """
        Initialization.

        Args:
            app: A Flask application.
            feature_policy: A string or dictionary describing the
                feature policy for the response.
            force_https: Redirects non-http requests to https, disabled in
                debug mode.
            force_https_permanent: Uses 301 instead of 302 redirects.
            frame_options: Sets the X-Frame-Options header, defaults to
                SAMEORIGIN.
            frame_options_allow_from: Used when frame_options is set to
                ALLOW_FROM and is a string of domains to allow frame embedding.
            strict_transport_security: Sets HSTS headers.
            strict_transport_security_preload: Enables HSTS preload. See
                https://hstspreload.org.
            strict_transport_security_max_age: How long HSTS headers are
                honored by the browser.
            strict_transport_security_include_subdomain: Whether to include
                all subdomains when setting HSTS.
            content_security_policy: A string or dictionary describing the
                enforcing content security policy for the response, or a
                dictionary with ``enforce`` and ``report_only`` entries.
            content_security_policy_enforce: Explicit enforcing CSP
                directives.  Takes precedence over
                ``content_security_policy`` when both are provided.
            content_security_policy_report_only_policy: Explicit directives
                for a separate report-only policy.  When this (or a
                dictionary/string passed as
                ``content_security_policy_report_only``) is present, the
                enforcing and report-only headers are emitted together.
            content_security_policy_report_uri: A string indicating the report
                URI used for CSP violation reports
            content_security_policy_report_to: A Reporting API endpoint group
                name used by the ``report-to`` directive.
            content_security_policy_report_to_endpoint: The Reporting API
                endpoint URL for
                ``content_security_policy_report_to``.
            content_security_policy_reporting_endpoints: A dictionary mapping
                Reporting API group names to endpoint URLs.
            content_security_policy_report_only: Either the legacy boolean
                switch to send the enforcing policy as report-only, or a
                dictionary/string containing a separate report-only policy.
                The legacy boolean form still requires a reporting endpoint.
            content_security_policy_nonce_in: A list of csp sections to include
                a per-request nonce value in
            content_security_policy_report_only_nonce_in: A list of report-only
                csp sections to include the per-request nonce value in.  When
                omitted, ``content_security_policy_nonce_in`` is used.
            referrer_policy: A string describing the referrer policy for the
                response.
            session_cookie_secure: Forces the session cookie to only be sent
                over https. Disabled in debug mode.
            session_cookie_http_only: Prevents JavaScript from reading the
                session cookie.
            force_file_save: Prevents the user from opening a file download
                directly on >= IE 8

        See README.rst for a detailed description of each option.
        """
        if isinstance(feature_policy, dict):
            self.feature_policy = OrderedDict(feature_policy)
        else:
            self.feature_policy = feature_policy
        self.force_https = force_https
        self.force_https_permanent = force_https_permanent

        self.frame_options = frame_options
        self.frame_options_allow_from = frame_options_allow_from

        self.strict_transport_security = strict_transport_security
        self.strict_transport_security_preload = \
            strict_transport_security_preload
        self.strict_transport_security_max_age = \
            strict_transport_security_max_age
        self.strict_transport_security_include_subdomains = \
            strict_transport_security_include_subdomains

        # A dictionary containing "enforce" and/or "report_only" is an
        # explicit dual-policy configuration.  Ordinary CSP dictionaries are
        # left untouched so existing dictionary CSPs keep working.
        dual_config = self._normalize_dual_policy_config(
            content_security_policy)
        nested_reporting_endpoints = None
        nested_report_uri = None
        nested_report_to = None
        nested_report_to_endpoint = None
        if dual_config is not None:
            nested_enforce = dual_config.get('enforce')
            nested_report_only = dual_config.get('report_only')
            nested_reporting_endpoints = dual_config.get(
                'reporting_endpoints')
            nested_report_uri = dual_config.get('report_uri')
            nested_report_to = dual_config.get('report_to')
            nested_report_to_endpoint = dual_config.get(
                'report_to_endpoint')
            if content_security_policy_enforce is None:
                content_security_policy_enforce = nested_enforce
            if content_security_policy_report_only is False and \
                    nested_report_only is not None:
                content_security_policy_report_only = nested_report_only
            if 'enforce' in dual_config:
                content_security_policy = dual_config['enforce']
            elif 'enforce_policy' in dual_config:
                content_security_policy = dual_config['enforce_policy']
            else:
                content_security_policy = DEFAULT_CSP_POLICY
        if content_security_policy_enforce is not None:
            content_security_policy = content_security_policy_enforce

        enforce_config = self._normalize_csp_config(
            content_security_policy)
        if enforce_config['policy'] is not None:
            content_security_policy = enforce_config['policy']
        self.content_security_policy = \
            self._copy_policy(content_security_policy)

        report_config = self._normalize_csp_config(
            content_security_policy_report_only)
        if report_config['policy'] is not None and \
                content_security_policy_report_only_policy is None:
            content_security_policy_report_only_policy = \
                report_config['policy']
        if report_config['report_uri'] is not None:
            content_security_policy_report_only_report_uri = \
                content_security_policy_report_only_report_uri or \
                report_config['report_uri']
        if report_config['report_to'] is not None:
            content_security_policy_report_only_report_to = \
                content_security_policy_report_only_report_to or \
                report_config['report_to']
        if report_config['report_to_endpoint'] is not None:
            content_security_policy_report_only_report_to_endpoint = \
                content_security_policy_report_only_report_to_endpoint or \
                report_config['report_to_endpoint']

        self.content_security_policy_report_only_policy = \
            self._copy_policy(content_security_policy_report_only_policy)
        if content_security_policy_report_only_policy is not None:
            self.content_security_policy_report_only = True
        elif isinstance(content_security_policy_report_only, bool):
            self.content_security_policy_report_only = \
                content_security_policy_report_only
        elif report_config['policy'] is not None:
            self.content_security_policy_report_only = True
        else:
            self.content_security_policy_report_only = \
                content_security_policy_report_only

        self.content_security_policy_report_uri = \
            content_security_policy_report_uri
        if self.content_security_policy_report_uri is None:
            self.content_security_policy_report_uri = nested_report_uri
        self.content_security_policy_report_to = \
            content_security_policy_report_to
        if self.content_security_policy_report_to is None:
            self.content_security_policy_report_to = \
                content_security_policy_report_to_group or nested_report_to
        self.content_security_policy_report_to_endpoint = \
            content_security_policy_report_to_endpoint
        if self.content_security_policy_report_to_endpoint is None:
            self.content_security_policy_report_to_endpoint = \
                content_security_policy_report_to_uri or \
                nested_report_to_endpoint
        self.content_security_policy_reporting_endpoints = \
            self._merge_reporting_endpoints(
                nested_reporting_endpoints,
                enforce_config['reporting_endpoints'],
                report_config['reporting_endpoints'],
                content_security_policy_reporting_endpoints)

        self.content_security_policy_enforce_report_uri = \
            content_security_policy_enforce_report_uri
        if self.content_security_policy_enforce_report_uri is None:
            self.content_security_policy_enforce_report_uri = \
                enforce_config['report_uri']
        self.content_security_policy_enforce_report_to = \
            content_security_policy_enforce_report_to
        if self.content_security_policy_enforce_report_to is None:
            self.content_security_policy_enforce_report_to = \
                enforce_config['report_to']
        self.content_security_policy_enforce_report_to_endpoint = \
            content_security_policy_enforce_report_to_endpoint
        if self.content_security_policy_enforce_report_to_endpoint is None:
            self.content_security_policy_enforce_report_to_endpoint = \
                enforce_config['report_to_endpoint']
        self.content_security_policy_report_only_report_uri = \
            content_security_policy_report_only_report_uri
        self.content_security_policy_report_only_report_to = \
            content_security_policy_report_only_report_to
        self.content_security_policy_report_only_report_to_endpoint = \
            content_security_policy_report_only_report_to_endpoint

        self.content_security_policy_nonce_in = list(
            content_security_policy_nonce_in or [])
        self.content_security_policy_report_only_nonce_in = \
            content_security_policy_report_only_nonce_in
        if self.content_security_policy_report_only_nonce_in is None and \
                report_config['nonce_in'] is not None:
            self.content_security_policy_report_only_nonce_in = \
                report_config['nonce_in']
        if self.content_security_policy_report_only_nonce_in is not None:
            self.content_security_policy_report_only_nonce_in = list(
                self.content_security_policy_report_only_nonce_in)

        # Validate values that are independent of the request before the
        # extension is attached to the application.
        self._validate_csp_configuration()

        app.jinja_env.globals['csp_nonce'] = self._get_nonce

        self.referrer_policy = referrer_policy

        self.session_cookie_secure = session_cookie_secure

        if session_cookie_http_only:
            app.config['SESSION_COOKIE_HTTPONLY'] = True

        self.force_file_save = force_file_save

        self.app = app

        app.before_request(self._force_https)
        app.before_request(self._make_nonce)
        app.after_request(self._set_response_headers)

    @property
    def content_security_policy_enforce(self):
        return self.content_security_policy

    @content_security_policy_enforce.setter
    def content_security_policy_enforce(self, value):
        self.content_security_policy = self._copy_policy(value)

    def _get_local_options(self):
        view_function = flask.current_app.view_functions.get(
            flask.request.endpoint)
        raw_view_options = getattr(
            view_function, 'talisman_view_options', {})
        view_options = dict(raw_view_options)

        view_options.setdefault('force_https', self.force_https)
        view_options.setdefault('frame_options', self.frame_options)
        view_options.setdefault(
            'frame_options_allow_from', self.frame_options_allow_from)
        view_options.setdefault(
            'feature_policy', self.feature_policy
        )
        view_options.setdefault('content_security_policy',
                                self.content_security_policy)
        view_options.setdefault('content_security_policy_enforce',
                                None)
        view_options.setdefault('content_security_policy_report_only',
                                self.content_security_policy_report_only)
        view_options.setdefault(
            'content_security_policy_report_only_policy',
            self.content_security_policy_report_only_policy)
        view_options.setdefault(
            'content_security_policy_report_uri',
            self.content_security_policy_report_uri)
        view_options.setdefault(
            'content_security_policy_report_to',
            self.content_security_policy_report_to)
        view_options.setdefault(
            'content_security_policy_report_to_endpoint',
            self.content_security_policy_report_to_endpoint)
        view_options.setdefault(
            'content_security_policy_reporting_endpoints',
            self.content_security_policy_reporting_endpoints)
        view_options.setdefault(
            'content_security_policy_enforce_report_uri',
            self.content_security_policy_enforce_report_uri)
        view_options.setdefault(
            'content_security_policy_enforce_report_to',
            self.content_security_policy_enforce_report_to)
        view_options.setdefault(
            'content_security_policy_enforce_report_to_endpoint',
            self.content_security_policy_enforce_report_to_endpoint)
        view_options.setdefault(
            'content_security_policy_report_only_report_uri',
            self.content_security_policy_report_only_report_uri)
        view_options.setdefault(
            'content_security_policy_report_only_report_to',
            self.content_security_policy_report_only_report_to)
        view_options.setdefault(
            'content_security_policy_report_only_report_to_endpoint',
            self.content_security_policy_report_only_report_to_endpoint)
        view_options.setdefault(
            'content_security_policy_nonce_in',
            self.content_security_policy_nonce_in)
        view_options.setdefault(
            'content_security_policy_report_only_nonce_in',
            self.content_security_policy_report_only_nonce_in)
        view_options['_raw_view_options'] = raw_view_options

        enforce_override = view_options.get(
            'content_security_policy_enforce')
        if 'content_security_policy_enforce' in raw_view_options:
            view_options['content_security_policy'] = enforce_override

        return view_options

    def _force_https(self):
        """Redirect any non-https requests to https.

        Based largely on flask-sslify.
        """

        if self.session_cookie_secure:
            if not self.app.debug:
                self.app.config['SESSION_COOKIE_SECURE'] = True

        criteria = [
            self.app.debug,
            flask.request.is_secure,
            flask.request.headers.get('X-Forwarded-Proto', 'http') == 'https',
        ]

        local_options = self._get_local_options()

        if local_options['force_https'] and not any(criteria):
            if flask.request.url.startswith('http://'):
                url = flask.request.url.replace('http://', 'https://', 1)
                code = 302
                if self.force_https_permanent:
                    code = 301
                r = flask.redirect(url, code=code)
                return r

    def _set_response_headers(self, response):
        """Applies all configured headers to the given response."""
        options = self._get_local_options()
        self._set_feature_headers(response.headers, options)
        self._set_frame_options_headers(response.headers, options)
        self._set_content_security_policy_headers(response.headers, options)
        self._set_hsts_headers(response.headers)
        self._set_referrer_policy_headers(response.headers)
        return response

    def _make_nonce(self):
        local_options = self._get_local_options()
        csp_options = self._resolve_csp_options(local_options)
        nonce_sections = (
            csp_options['enforce_nonce_in'] +
            csp_options['report_only_nonce_in'])
        if (
                nonce_sections and
                (csp_options['enforce_policy'] or
                 csp_options['report_only_policy']) and
                not getattr(flask.request, 'csp_nonce', None)):
            flask.request.csp_nonce = get_random_string(NONCE_LENGTH)

    def _get_nonce(self):
        return getattr(flask.request, 'csp_nonce', '')

    @staticmethod
    def _copy_policy(policy):
        if isinstance(policy, dict):
            return OrderedDict(policy)
        return policy

    @staticmethod
    def _normalize_dual_policy_config(policy):
        """Return a dual-policy config dictionary, or None.

        A dual-policy dictionary is distinguished from an ordinary CSP
        directive dictionary by its keys: ``enforce`` and/or ``report_only``.
        CSP itself has no directives with those names.
        """
        if not isinstance(policy, dict):
            return None

        lowered = dict((str(key).lower(), key) for key in policy)
        trigger_keys = (
            'enforce', 'enforce_policy', 'report_only', 'report-only',
            'reportonly', 'report_only_policy',
        )
        if not any(key in lowered for key in trigger_keys):
            return None

        dual_keys = trigger_keys + (
            'report_uri', 'report-uri', 'report-to', 'report_to',
            'report-to-endpoint', 'report_to_endpoint',
            'reporting_endpoints',
        )

        result = {}
        for key in dual_keys:
            if key in lowered:
                normalized = key.replace(
                    'report-only', 'report_only').replace(
                    'reportonly', 'report_only').replace(
                    'report-uri', 'report_uri').replace(
                    'report-to-endpoint', 'report_to_endpoint').replace(
                    'report-to', 'report_to')
                result[normalized] = policy[lowered[key]]
        if 'enforce_policy' in result:
            result.setdefault('enforce', result['enforce_policy'])
        if 'report_only_policy' in result:
            result.setdefault('report_only', result['report_only_policy'])
        return result

    @classmethod
    def _normalize_csp_config(cls, value):
        """Split a policy value into directives and reporting settings."""
        result = {
            'policy': value,
            'report_uri': None,
            'report_to': None,
            'report_to_endpoint': None,
            'reporting_endpoints': None,
            'nonce_in': None,
        }
        if value is None or isinstance(value, bool):
            result['policy'] = None
            return result
        if not isinstance(value, dict):
            return result

        lowered = dict((str(key).lower(), key) for key in value)
        if not any(key in lowered for key in _CSP_CONFIG_KEYS):
            return result

        def get(*keys):
            for key in keys:
                if key in lowered:
                    return value[lowered[key]]
            return None

        policy = get('directives', 'policy')
        if policy is None:
            policy = OrderedDict(
                (key, content) for key, content in iteritems(value)
                if str(key).lower() not in _CSP_CONFIG_KEYS)
            if not policy:
                policy = None
        result['policy'] = policy
        result['report_uri'] = get('report_uri', 'report-uri')
        result['report_to'] = get('report_to', 'report-to')
        result['report_to_endpoint'] = get(
            'report_to_endpoint', 'report_to_uri', 'report-to-endpoint',
            'endpoint')
        result['reporting_endpoints'] = get(
            'reporting_endpoints', 'reporting-endpoints')
        result['nonce_in'] = get('nonce_in')
        return result

    @staticmethod
    def _policy_is_enabled(policy):
        if policy is None or policy is False:
            return False
        if isinstance(policy, string_types):
            return bool(policy.strip())
        if isinstance(policy, dict):
            return bool(policy)
        return bool(policy)

    @staticmethod
    def _merge_reporting_endpoints(*mappings):
        result = OrderedDict()
        for mapping in mappings:
            if mapping is None:
                continue
            if not isinstance(mapping, dict):
                raise ValueError(
                    'Reporting endpoints must be provided as a dictionary')
            for group, endpoint in iteritems(mapping):
                result[group] = endpoint
        return result

    @staticmethod
    def _validate_report_to_group(group):
        if not isinstance(group, string_types) or not group:
            raise ValueError(
                'CSP report-to group names must be non-empty HTTP tokens')
        if not _REPORT_TO_TOKEN_RE.match(group):
            raise ValueError(
                'CSP report-to group names must be valid HTTP tokens')
        return group

    @staticmethod
    def _sanitize_report_endpoint(endpoint):
        if not isinstance(endpoint, string_types) or not endpoint:
            raise ValueError(
                'A CSP reporting endpoint must be a non-empty URL')
        if '\r' in endpoint or '\n' in endpoint:
            raise ValueError('A CSP reporting endpoint contains invalid data')
        # Drop the query and fragment without echoing either value.  This
        # keeps endpoint capability tokens out of response headers and error
        # messages.
        sanitized = endpoint.split('?', 1)[0].split('#', 1)[0]
        if not sanitized or '"' in sanitized:
            raise ValueError('A CSP reporting endpoint contains invalid data')
        return sanitized

    def _normalize_report_to(self, report_to, endpoint, endpoints):
        """Resolve a report-to group and its endpoint mapping."""
        mapping = OrderedDict()
        if endpoints is not None:
            if not isinstance(endpoints, dict):
                raise ValueError(
                    'Reporting endpoints must be provided as a dictionary')
            for group, value in iteritems(endpoints):
                self._validate_report_to_group(group)
                mapping[group] = self._sanitize_report_endpoint(value)

        group = None
        if isinstance(report_to, dict):
            lowered = dict(
                (str(key).lower(), key) for key in report_to)
            config_keys = ('group', 'name', 'endpoint', 'url', 'uri')
            if any(key in lowered for key in config_keys):
                if 'group' in lowered:
                    group = report_to[lowered['group']]
                elif 'name' in lowered:
                    group = report_to[lowered['name']]
                for key in ('endpoint', 'url', 'uri'):
                    if key in lowered and endpoint is None:
                        endpoint = report_to[lowered[key]]
            else:
                for item_group, value in iteritems(report_to):
                    self._validate_report_to_group(item_group)
                    mapping[item_group] = \
                        self._sanitize_report_endpoint(value)
                if len(mapping) == 1:
                    group = next(iter(mapping))
                elif mapping:
                    raise ValueError(
                        'A report-to configuration must identify one group')
        elif isinstance(report_to, (list, tuple)):
            if len(report_to) != 2:
                raise ValueError(
                    'A report-to configuration must be a group and endpoint')
            group, group_endpoint = report_to
            if endpoint is None:
                endpoint = group_endpoint
        elif report_to is not None:
            group = report_to

        if group is not None:
            self._validate_report_to_group(group)
        elif len(mapping) == 1:
            group = next(iter(mapping))

        if endpoint is not None:
            if group is None:
                raise ValueError(
                    'A report-to endpoint requires a group name')
            mapping[group] = self._sanitize_report_endpoint(endpoint)

        if group is not None and group not in mapping:
            raise ValueError('A report-to group requires a reporting endpoint')

        return group, mapping

    def _policy_entries(self, policy):
        """Parse a CSP string or dictionary into an ordered entry list."""
        entries = []
        seen = set()
        if not self._policy_is_enabled(policy):
            return entries

        if isinstance(policy, string_types):
            for policy_part in policy.split(';'):
                policy_part = policy_part.strip()
                if not policy_part:
                    continue
                policy_parts = policy_part.split()
                section = policy_parts[0]
                content = ' '.join(policy_parts[1:])
                lower_section = section.lower()
                if lower_section in seen:
                    raise ValueError(
                        'Duplicate CSP directive: {}'.format(section))
                seen.add(lower_section)
                entries.append([section, content])
        elif isinstance(policy, dict):
            for section, content in iteritems(policy):
                lower_section = str(section).lower()
                if lower_section in seen:
                    raise ValueError(
                        'Duplicate CSP directive: {}'.format(section))
                seen.add(lower_section)
                if content is None:
                    content = ''
                elif not isinstance(content, string_types):
                    try:
                        content = ' '.join(content)
                    except TypeError:
                        content = str(content)
                entries.append([section, content])
        else:
            raise ValueError(
                'A CSP policy must be a string or dictionary')
        return entries

    @staticmethod
    def _find_policy_entry(entries, directive):
        for index, entry in enumerate(entries):
            if entry[0].lower() == directive:
                return index
        return None

    def _serialize_policy(self, entries):
        policies = []
        for section, content in entries:
            content = content.strip()
            if content:
                policies.append('{} {}'.format(section, content))
            else:
                policies.append(str(section))
        return '; '.join(policies)

    def _parse_policy(self, policy, nonce_sections=None):
        entries = self._policy_entries(policy)
        if nonce_sections:
            nonce_sections = set(
                str(section).lower() for section in nonce_sections)
            nonce = getattr(flask.request, 'csp_nonce', None)
            if nonce:
                for entry in entries:
                    if entry[0].lower() not in nonce_sections:
                        continue
                    if entry[1]:
                        entry[1] += " 'nonce-{}'".format(nonce)
                    else:
                        entry[1] = "'nonce-{}'".format(nonce)
        return self._serialize_policy(entries)

    def _apply_policy_reporting(
            self, entries, report_uri, report_to, endpoint, endpoints,
            conflict_mode=False):
        """Apply report-uri/report-to directives and return used endpoints."""
        group, mapping = self._normalize_report_to(
            report_to, endpoint, endpoints)

        report_uri_index = self._find_policy_entry(entries, 'report-uri')
        if report_uri_index is not None:
            values = entries[report_uri_index][1].split()
            if not values:
                raise ValueError('A report-uri directive requires an endpoint')
            entries[report_uri_index][1] = ' '.join(
                self._sanitize_report_endpoint(value)
                for value in values)
            if report_uri is not None:
                sanitized_uri = self._sanitize_report_endpoint(report_uri)
                if entries[report_uri_index][1] != sanitized_uri:
                    if conflict_mode:
                        raise ValueError(
                            'Conflicting report-uri directives')
        elif report_uri is not None:
            entries.append([
                'report-uri', self._sanitize_report_endpoint(report_uri)])

        report_to_index = self._find_policy_entry(entries, 'report-to')
        used_endpoints = OrderedDict()
        if report_to_index is not None:
            values = entries[report_to_index][1].split()
            if len(values) != 1:
                raise ValueError(
                    'A report-to directive requires one group name')
            inline_group = self._validate_report_to_group(values[0])
            if group is not None and inline_group != group and conflict_mode:
                raise ValueError('Conflicting report-to directives')
            if inline_group not in mapping:
                raise ValueError(
                    'A report-to group requires a reporting endpoint')
            used_endpoints[inline_group] = mapping[inline_group]
        elif group is not None:
            entries.append(['report-to', group])
            used_endpoints[group] = mapping[group]

        return entries, used_endpoints

    def _resolve_csp_options(self, options):
        """Resolve enforcing/report-only policies for a request."""
        raw = options.get('_raw_view_options') or {}
        enforce_policy = options.get('content_security_policy')

        route_dual = self._normalize_dual_policy_config(enforce_policy)
        if route_dual is not None:
            if 'enforce' in route_dual:
                enforce_policy = route_dual['enforce']
            elif 'enforce_policy' in route_dual:
                enforce_policy = route_dual['enforce_policy']
            else:
                enforce_policy = self.content_security_policy
        enforce_config = self._normalize_csp_config(enforce_policy)
        if enforce_config['policy'] is not None:
            enforce_policy = enforce_config['policy']

        report_setting = options.get(
            'content_security_policy_report_only')
        explicit_report_policy = options.get(
            'content_security_policy_report_only_policy')
        report_config = self._normalize_csp_config(report_setting)

        if route_dual is not None and \
                'content_security_policy_report_only' not in raw and \
                'content_security_policy_report_only_policy' not in raw:
            route_report = route_dual.get('report_only')
            if route_report is not None:
                report_setting = route_report
                report_config = self._normalize_csp_config(route_report)
            route_endpoints = route_dual.get('reporting_endpoints')
            if route_endpoints is not None:
                options = dict(options)
                options['content_security_policy_reporting_endpoints'] = \
                    self._merge_reporting_endpoints(
                        options.get(
                            'content_security_policy_reporting_endpoints'),
                        route_endpoints)

        route_report_disable = False
        if route_dual is not None and 'report_only' in route_dual:
            route_report_value = route_dual['report_only']
            if isinstance(route_report_value, bool):
                route_report_disable = not route_report_value
            elif not self._policy_is_enabled(route_report_value):
                route_report_disable = True
        if 'content_security_policy_report_only' in raw:
            route_value = raw['content_security_policy_report_only']
            if isinstance(route_value, bool):
                route_report_disable = not route_value
            elif not self._policy_is_enabled(route_value):
                route_report_disable = True
        if 'content_security_policy_report_only_policy' in raw and \
                raw['content_security_policy_report_only_policy'] is None:
            route_report_disable = True
        if route_report_disable and \
                'content_security_policy_report_only_policy' not in raw:
            explicit_report_policy = None

        if isinstance(report_setting, bool):
            legacy_report_only = report_setting and \
                not self._policy_is_enabled(explicit_report_policy)
            report_enabled = report_setting or \
                self._policy_is_enabled(explicit_report_policy)
        else:
            if report_config['policy'] is not None:
                explicit_report_policy = report_config['policy']
            legacy_report_only = False
            config_reporting = any(
                report_config[key] is not None
                for key in (
                    'report_uri', 'report_to', 'report_to_endpoint',
                    'reporting_endpoints'))
            report_enabled = (
                self._policy_is_enabled(explicit_report_policy) or
                config_reporting)
            if report_enabled and \
                    not self._policy_is_enabled(explicit_report_policy):
                legacy_report_only = True

        if not report_enabled:
            explicit_report_policy = None
            legacy_report_only = False

        if route_report_disable and \
                self._policy_is_enabled(enforce_policy):
            raise ValueError(
                'A route override cannot disable report-only CSP while '
                'retaining an enforcing policy')

        # Report-only-specific settings take precedence over the shared
        # report settings, which in turn take precedence over wrapper
        # values.
        def first_not_none(*values):
            for value in values:
                if value is not None:
                    return value
            return None

        report_uri = first_not_none(
            options.get('content_security_policy_report_only_report_uri'),
            report_config['report_uri'],
            options.get('content_security_policy_report_uri'))
        report_to = first_not_none(
            options.get('content_security_policy_report_only_report_to'),
            report_config['report_to'],
            options.get('content_security_policy_report_to'))
        report_endpoint = first_not_none(
            options.get(
                'content_security_policy_report_only_report_to_endpoint'),
            report_config['report_to_endpoint'],
            options.get('content_security_policy_report_to_endpoint'))
        enforce_report_uri = first_not_none(
            options.get('content_security_policy_enforce_report_uri'),
            enforce_config['report_uri'])
        enforce_report_to = first_not_none(
            options.get('content_security_policy_enforce_report_to'),
            enforce_config['report_to'])
        enforce_endpoint = first_not_none(
            options.get('content_security_policy_enforce_report_to_endpoint'),
            enforce_config['report_to_endpoint'])
        reporting_endpoints = self._merge_reporting_endpoints(
            options.get('content_security_policy_reporting_endpoints'),
            enforce_config['reporting_endpoints'],
            report_config['reporting_endpoints'])
        if not report_enabled or legacy_report_only:
            if enforce_report_uri is None:
                enforce_report_uri = report_uri
            if enforce_report_to is None:
                enforce_report_to = report_to
            if enforce_endpoint is None:
                enforce_endpoint = report_endpoint

        enforce_nonce_in = list(
            options.get('content_security_policy_nonce_in') or [])
        report_nonce_in = options.get(
            'content_security_policy_report_only_nonce_in')
        if report_nonce_in is None:
            report_nonce_in = enforce_nonce_in
        else:
            report_nonce_in = list(report_nonce_in)

        return {
            'enforce_policy': self._copy_policy(enforce_policy),
            'report_only_policy': self._copy_policy(
                explicit_report_policy),
            'legacy_report_only': legacy_report_only,
            'report_enabled': report_enabled,
            'report_uri': report_uri,
            'report_to': report_to,
            'report_endpoint': report_endpoint,
            'reporting_endpoints': reporting_endpoints,
            'enforce_report_uri': enforce_report_uri,
            'enforce_report_to': enforce_report_to,
            'enforce_endpoint': enforce_endpoint,
            'enforce_nonce_in': enforce_nonce_in,
            'report_only_nonce_in': report_nonce_in,
        }

    def _build_csp_headers(self, options, include_nonce=True):
        """Build CSP headers and the Reporting-Endpoints header value."""
        csp = self._resolve_csp_options(options)
        headers = OrderedDict()
        used_endpoints = OrderedDict()

        enforce_policy = csp['enforce_policy']
        report_policy = csp['report_only_policy']
        legacy_report_only = csp['legacy_report_only']
        report_enabled = csp['report_enabled']
        dual_mode = report_enabled and not legacy_report_only and \
            self._policy_is_enabled(enforce_policy)

        if not legacy_report_only and \
                self._policy_is_enabled(enforce_policy):
            nonce_sections = csp['enforce_nonce_in'] if include_nonce else []
            entries = self._policy_entries(enforce_policy)
            if self._policy_is_enabled(enforce_policy):
                entries, used = self._apply_policy_reporting(
                    entries, csp['enforce_report_uri'],
                    csp['enforce_report_to'], csp['enforce_endpoint'],
                    csp['reporting_endpoints'], conflict_mode=dual_mode)
                used_endpoints.update(used)
                headers[_CSP_HEADER] = self._serialize_policy(
                    self._add_nonce_to_entries(entries, nonce_sections))

        if report_enabled:
            if not self._policy_is_enabled(report_policy):
                report_policy = enforce_policy
            if self._policy_is_enabled(report_policy):
                nonce_sections = csp['report_only_nonce_in'] \
                    if include_nonce else []
                entries = self._policy_entries(report_policy)
                entries, used = self._apply_policy_reporting(
                    entries, csp['report_uri'], csp['report_to'],
                    csp['report_endpoint'], csp['reporting_endpoints'],
                    conflict_mode=dual_mode)
                if self._find_policy_entry(
                        entries, 'report-uri') is None and \
                        self._find_policy_entry(entries, 'report-to') is None:
                    raise ValueError(
                        'A report-only CSP policy requires a reporting '
                        'endpoint')
                used_endpoints.update(used)
                headers[_CSP_RO_HEADER] = self._serialize_policy(
                    self._add_nonce_to_entries(entries, nonce_sections))

        endpoints_header = None
        if used_endpoints:
            endpoints_header = ', '.join(
                '{}="{}"'.format(group, endpoint)
                for group, endpoint in iteritems(used_endpoints))
        return headers, endpoints_header

    @staticmethod
    def _add_nonce_to_entries(entries, nonce_sections):
        if not nonce_sections:
            return entries
        nonce_sections = set(
            str(section).lower() for section in nonce_sections)
        nonce = getattr(flask.request, 'csp_nonce', None)
        if not nonce:
            return entries
        for entry in entries:
            if entry[0].lower() not in nonce_sections:
                continue
            if entry[1]:
                entry[1] += " 'nonce-{}'".format(nonce)
            else:
                entry[1] = "'nonce-{}'".format(nonce)
        return entries

    def _initial_csp_options(self):
        return {
            'content_security_policy': self.content_security_policy,
            'content_security_policy_enforce': None,
            'content_security_policy_report_only':
                self.content_security_policy_report_only,
            'content_security_policy_report_only_policy':
                self.content_security_policy_report_only_policy,
            'content_security_policy_report_uri':
                self.content_security_policy_report_uri,
            'content_security_policy_report_to':
                self.content_security_policy_report_to,
            'content_security_policy_report_to_endpoint':
                self.content_security_policy_report_to_endpoint,
            'content_security_policy_reporting_endpoints':
                self.content_security_policy_reporting_endpoints,
            'content_security_policy_enforce_report_uri':
                self.content_security_policy_enforce_report_uri,
            'content_security_policy_enforce_report_to':
                self.content_security_policy_enforce_report_to,
            'content_security_policy_enforce_report_to_endpoint':
                self.content_security_policy_enforce_report_to_endpoint,
            'content_security_policy_report_only_report_uri':
                self.content_security_policy_report_only_report_uri,
            'content_security_policy_report_only_report_to':
                self.content_security_policy_report_only_report_to,
            'content_security_policy_report_only_report_to_endpoint':
                self.content_security_policy_report_only_report_to_endpoint,
            'content_security_policy_nonce_in': [],
            'content_security_policy_report_only_nonce_in': [],
            '_raw_view_options': {},
        }

    def _validate_csp_configuration(self):
        """Validate the initial CSP configuration without a request."""
        for report_uri, report_to, endpoint in (
                (self.content_security_policy_report_uri,
                 self.content_security_policy_report_to,
                 self.content_security_policy_report_to_endpoint),
                (self.content_security_policy_enforce_report_uri,
                 self.content_security_policy_enforce_report_to,
                 self.content_security_policy_enforce_report_to_endpoint),
                (self.content_security_policy_report_only_report_uri,
                 self.content_security_policy_report_only_report_to,
                 self.content_security_policy_report_only_report_to_endpoint)):
            if report_uri is not None:
                self._sanitize_report_endpoint(report_uri)
            self._normalize_report_to(
                report_to, endpoint,
                self.content_security_policy_reporting_endpoints)
        self._normalize_report_to(
            None, None, self.content_security_policy_reporting_endpoints)
        self._build_csp_headers(
            self._initial_csp_options(), include_nonce=False)

    def _set_feature_headers(self, headers, options):
        if not options['feature_policy']:
            return

        policy = options['feature_policy']
        policy = self._parse_policy(policy, [])

        headers['Feature-Policy'] = policy

    def _set_frame_options_headers(self, headers, options):
        if not options['frame_options']:
            return
        headers['X-Frame-Options'] = options['frame_options']

        if options['frame_options'] == ALLOW_FROM:
            headers['X-Frame-Options'] += " {}".format(
                options['frame_options_allow_from'])

    def _set_content_security_policy_headers(self, headers, options):
        headers['X-XSS-Protection'] = '1; mode=block'
        headers['X-Content-Type-Options'] = 'nosniff'

        if self.force_file_save:
            headers['X-Download-Options'] = 'noopen'

        csp_headers, endpoints_header = self._build_csp_headers(options)
        for header, value in iteritems(csp_headers):
            headers[header] = value
        if endpoints_header is not None:
            headers[_REPORTING_ENDPOINTS_HEADER] = endpoints_header

    def _set_hsts_headers(self, headers):
        criteria = [
            flask.request.is_secure,
            flask.request.headers.get('X-Forwarded-Proto', 'http') == 'https',
        ]
        if not self.strict_transport_security or not any(criteria):
            return

        value = 'max-age={}'.format(self.strict_transport_security_max_age)

        if self.strict_transport_security_include_subdomains:
            value += '; includeSubDomains'

        if self.strict_transport_security_preload:
            value += '; preload'

        headers['Strict-Transport-Security'] = value

    def _set_referrer_policy_headers(self, headers):
        headers['Referrer-Policy'] = self.referrer_policy

    def __call__(self, **kwargs):
        """Use talisman as a decorator to configure options for a particular
        view.

        Only frame_options, frame_options_allow_from, content_security_policy
        (or content_security_policy_enforce), and the report-only CSP options
        can be set on a per-view basis.

        Example:

            app = Flask(__name__)
            talisman = Talisman(app)

            @app.route('/normal')
            def normal():
                return 'Normal'

            @app.route('/embeddable')
            @talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
            def embeddable():
                return 'Embeddable'
        """
        route_enforce = kwargs.get(
            'content_security_policy_enforce',
            kwargs.get(
                'content_security_policy', self.content_security_policy))
        route_dual = self._normalize_dual_policy_config(route_enforce)
        if route_dual is not None:
            if 'enforce' in route_dual:
                route_enforce = route_dual['enforce']
            else:
                route_enforce = self.content_security_policy

        disabled = False
        if 'content_security_policy_report_only' in kwargs:
            value = kwargs['content_security_policy_report_only']
            if isinstance(value, bool):
                disabled = not value
            else:
                disabled = not self._policy_is_enabled(value)
        if 'content_security_policy_report_only_policy' in kwargs and \
                kwargs['content_security_policy_report_only_policy'] is None:
            disabled = True
        if route_dual is not None and 'report_only' in route_dual:
            value = route_dual['report_only']
            if not self._policy_is_enabled(value):
                disabled = True
        if disabled and self._policy_is_enabled(route_enforce):
            raise ValueError(
                'A route override cannot disable report-only CSP while '
                'retaining an enforcing policy')

        def decorator(f):
            setattr(f, 'talisman_view_options', kwargs)
            return f
        return decorator


try:
    import secrets

    def get_random_string(length):  # pragma: no cover
        # Note token_urlsafe returns a 'length'-byte string which is then
        # base64 encoded so is longer than length, so only return last
        # 'length' characters.
        return secrets.token_urlsafe(length)[:length]

except ImportError:  # pragma: no cover
    import random
    import string
    rnd = random.SystemRandom()

    def get_random_string(length):
        allowed_chars = (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits)
        return ''.join(
            rnd.choice(allowed_chars)
            for _ in range(length))
