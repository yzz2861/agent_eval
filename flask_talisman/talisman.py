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

DEFAULT_PERMISSIONS_POLICY = {
}

NONCE_LENGTH = 16

# Directive names such as ``camera`` or ``interest-cohort``. Unknown
# directives are passed through but must still be syntactically valid.
PERMISSIONS_POLICY_DIRECTIVE_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$')

# A serialized origin: scheme://host[:port] with an optional wildcard
# subdomain. Paths, queries and fragments are not allowed.
PERMISSIONS_POLICY_ORIGIN_RE = re.compile(
    r'^[a-zA-Z][a-zA-Z0-9+.-]*://'
    r'(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?'
    r'(:[0-9]+)?$')

# Tokens inside a permissions policy allowlist, e.g. ``self`` or
# ``"https://example.com"``.
PERMISSIONS_POLICY_ALLOWLIST_ITEM_RE = re.compile(
    r'"[^"]*"|\'[^\']*\'|\S+')


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
            permissions_policy=DEFAULT_PERMISSIONS_POLICY,
            legacy_feature_policy=False,
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
            session_cookie_http_only=True):
        """
        Initialization.

        Args:
            app: A Flask application.
            feature_policy: A string or dictionary describing the
                legacy Feature-Policy header for the response. Only sent
                when legacy_feature_policy is enabled.
            permissions_policy: A string or dictionary describing the
                Permissions-Policy header for the response.
            legacy_feature_policy: Send the legacy Feature-Policy header
                for feature_policy instead of ignoring it. Cannot be
                combined with permissions_policy.
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
                content security policy for the response.
            content_security_policy_report_uri: A string indicating the report
                URI used for CSP violation reports
            content_security_policy_report_only: Whether to set the CSP header
                as "report-only", which disables the enforcement by the browser
                and requires a "report-uri" parameter with a backend to receive
                the POST data
            content_security_policy_nonce_in: A list of csp sections to include
                a per-request nonce value in
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

        if isinstance(permissions_policy, dict):
            self.permissions_policy = OrderedDict(permissions_policy)
        else:
            self.permissions_policy = permissions_policy

        self.legacy_feature_policy = legacy_feature_policy

        if (self.legacy_feature_policy and self.feature_policy and
                self.permissions_policy):
            raise ValueError(
                'The legacy Feature-Policy header cannot be combined with '
                'Permissions-Policy; disable legacy_feature_policy or '
                'remove one of the policies')

        if self.permissions_policy:
            # Validate eagerly so configuration errors surface at startup.
            self._parse_permissions_policy(self.permissions_policy)

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

        if isinstance(content_security_policy, dict):
            self.content_security_policy = OrderedDict(content_security_policy)
        else:
            self.content_security_policy = content_security_policy
        self.content_security_policy_report_uri = \
            content_security_policy_report_uri
        self.content_security_policy_report_only = \
            content_security_policy_report_only
        if self.content_security_policy_report_only and \
                self.content_security_policy_report_uri is None:
            raise ValueError(
                'Setting content_security_policy_report_only to True also '
                'requires a URI to be specified in '
                'content_security_policy_report_uri')
        self.content_security_policy_nonce_in = (
            content_security_policy_nonce_in or []
        )

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

    def _get_local_options(self):
        view_function = flask.current_app.view_functions.get(
            flask.request.endpoint)
        view_options = dict(getattr(
            view_function, 'talisman_view_options', {}))

        view_options.setdefault('force_https', self.force_https)
        view_options.setdefault('frame_options', self.frame_options)
        view_options.setdefault(
            'frame_options_allow_from', self.frame_options_allow_from)
        view_options.setdefault(
            'content_security_policy', self.content_security_policy)

        # Feature and permissions policies are merged per-directive:
        # view-level directives override global directives with the same
        # name, all other global directives are kept.
        view_options['feature_policy'] = self._merge_view_policy(
            self.feature_policy, view_options, 'feature_policy',
            self._feature_policy_string_to_dict)
        view_options['permissions_policy'] = self._merge_view_policy(
            self.permissions_policy, view_options, 'permissions_policy',
            self._permissions_policy_string_to_dict)

        return view_options

    def _merge_view_policy(self, global_policy, view_options, key,
                           string_to_dict):
        """Merge a global policy with view-level overrides.

        View-level directives take precedence over global directives with
        the same name. Setting the option to ``None`` or ``False`` on a
        view disables the header for that view.
        """
        if key not in view_options:
            return global_policy

        view_policy = view_options[key]
        if view_policy is None or view_policy is False:
            return None
        if not view_policy:
            return global_policy
        if not global_policy:
            return view_policy

        merged = self._policy_to_ordered_dict(global_policy, string_to_dict)
        merged.update(self._policy_to_ordered_dict(view_policy,
                                                   string_to_dict))
        return merged

    def _policy_to_ordered_dict(self, policy, string_to_dict):
        if isinstance(policy, string_types):
            return string_to_dict(policy)
        return OrderedDict(policy)

    def _feature_policy_string_to_dict(self, policy_string):
        policy = OrderedDict()
        for policy_part in policy_string.split(';'):
            policy_part = policy_part.strip()
            if not policy_part:
                continue
            policy_parts = policy_part.split(' ')
            policy[policy_parts[0]] = ' '.join(policy_parts[1:])
        return policy

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
        if (
                local_options['content_security_policy'] and
                self.content_security_policy_nonce_in and
                not getattr(flask.request, 'csp_nonce', None)):
            flask.request.csp_nonce = get_random_string(NONCE_LENGTH)

    def _get_nonce(self):
        return getattr(flask.request, 'csp_nonce', '')

    def _parse_policy(self, policy):
        if isinstance(policy, string_types):
            # parse the string into a policy dict
            policy_string = policy
            policy = OrderedDict()

            for policy_part in policy_string.split(';'):
                policy_parts = policy_part.strip().split(' ')
                policy[policy_parts[0]] = " ".join(policy_parts[1:])

        policies = []
        for section, content in iteritems(policy):
            if not isinstance(content, string_types):
                content = ' '.join(content)
            policy_part = '{} {}'.format(section, content)

            if (
                    hasattr(flask.request, 'csp_nonce') and
                    section in self.content_security_policy_nonce_in):
                policy_part += " 'nonce-{}'".format(flask.request.csp_nonce)

            policies.append(policy_part)

        policy = '; '.join(policies)

        return policy

    def _permissions_policy_string_to_dict(self, policy_string):
        policy = OrderedDict()
        for part in self._split_permissions_policy(policy_string):
            directive, separator, allowlist = part.partition('=')
            if not separator:
                raise ValueError(
                    'Invalid Permissions-Policy: expected '
                    '"directive=allowlist" entries')
            directive = directive.strip()
            allowlist = allowlist.strip()
            if allowlist == '*':
                policy[directive] = ['*']
            elif allowlist.startswith('(') and allowlist.endswith(')'):
                items = PERMISSIONS_POLICY_ALLOWLIST_ITEM_RE.findall(
                    allowlist[1:-1])
                policy[directive] = items
            else:
                raise ValueError(
                    'Invalid Permissions-Policy allowlist for directive '
                    "'{}'".format(directive))
        return policy

    def _split_permissions_policy(self, policy_string):
        parts = []
        depth = 0
        current = []
        for char in policy_string:
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0:
                    raise ValueError(
                        'Unbalanced parentheses in Permissions-Policy')
            if char == ',' and depth == 0:
                parts.append(''.join(current))
                current = []
            else:
                current.append(char)
        if depth != 0:
            raise ValueError('Unbalanced parentheses in Permissions-Policy')
        parts.append(''.join(current))
        return [part.strip() for part in parts if part.strip()]

    def _parse_permissions_policy(self, policy):
        if isinstance(policy, string_types):
            policy = self._permissions_policy_string_to_dict(policy)

        parts = []
        for directive, allowlist in iteritems(policy):
            directive = directive.strip()
            if not PERMISSIONS_POLICY_DIRECTIVE_RE.match(directive):
                raise ValueError(
                    'Invalid Permissions-Policy directive name: '
                    '{!r}'.format(directive))
            parts.append('{}={}'.format(
                directive,
                self._parse_permissions_allowlist(directive, allowlist)))

        return ', '.join(parts)

    def _parse_permissions_allowlist(self, directive, allowlist):
        if allowlist is None:
            return '()'
        if isinstance(allowlist, string_types):
            items = allowlist.split()
        else:
            items = list(allowlist)

        normalized = []
        for item in items:
            token = item.strip()
            if (len(token) >= 2 and token[0] == token[-1] and
                    token[0] in ('\'', '"')):
                token = token[1:-1]
            if token == 'self':
                normalized.append('self')
            elif token == '*':
                normalized.append('*')
            elif token == 'none':
                normalized.append('none')
            else:
                self._validate_permissions_origin(directive, token)
                normalized.append('"{}"'.format(token))

        if 'none' in normalized:
            if len(normalized) > 1:
                raise ValueError(
                    "Permissions-Policy directive '{}' cannot combine "
                    "'none' with other allowlist entries".format(directive))
            return '()'
        if '*' in normalized:
            if len(normalized) > 1:
                raise ValueError(
                    "Permissions-Policy directive '{}' cannot combine "
                    "'*' with other allowlist entries".format(directive))
            return '*'
        if not normalized:
            return '()'
        return '({})'.format(' '.join(normalized))

    def _validate_permissions_origin(self, directive, origin):
        if not PERMISSIONS_POLICY_ORIGIN_RE.match(origin):
            # The raw origin is deliberately not included in the message
            # so that sensitive query strings are never leaked.
            raise ValueError(
                "Invalid origin in Permissions-Policy directive '{}'; "
                'origins must be serialized as scheme://host[:port] '
                'without path, query or fragment'.format(directive))

    def _set_feature_headers(self, headers, options):
        permissions_policy = options.get('permissions_policy')
        feature_policy = options.get('feature_policy')

        if (permissions_policy and feature_policy and
                self.legacy_feature_policy):
            raise ValueError(
                'The legacy Feature-Policy header cannot be combined with '
                'Permissions-Policy; disable legacy_feature_policy or '
                'remove one of the policies')

        if permissions_policy:
            headers['Permissions-Policy'] = self._parse_permissions_policy(
                permissions_policy)
        elif self.legacy_feature_policy and feature_policy:
            headers['Feature-Policy'] = self._parse_policy(feature_policy)

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

        if not options['content_security_policy']:
            return

        policy = options['content_security_policy']
        policy = self._parse_policy(policy)

        if self.content_security_policy_report_uri and \
                'report-uri' not in policy:
            policy += '; report-uri ' + self.content_security_policy_report_uri

        csp_header = 'Content-Security-Policy'
        if self.content_security_policy_report_only:
            csp_header += '-Report-Only'

        headers[csp_header] = policy

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

        Only frame_options, frame_options_allow_from,
        content_security_policy, feature_policy, and permissions_policy
        can be set on a per-view basis. feature_policy and
        permissions_policy are merged with the global configuration
        per-directive; view-level directives take precedence over global
        directives with the same name.

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
