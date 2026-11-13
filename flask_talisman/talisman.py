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
from collections import OrderedDict

import flask
from six import iteritems, string_types


DENY = 'DENY'
SAMEORIGIN = 'SAMEORIGIN'
ALLOW_FROM = 'ALLOW-FROM'
ONE_YEAR_IN_SECS = 31556926

# Categories used to describe the embedding sources configured through the
# CSP ``frame-ancestors`` directive. They deliberately describe the *kind* of
# source only and never carry a concrete origin, so they are safe to reuse in
# error messages and audit records.
FRAME_ANCESTORS_NONE = 'none'
FRAME_ANCESTORS_SELF = 'self'
FRAME_ANCESTORS_SINGLE_ORIGIN = 'single-origin'
FRAME_ANCESTORS_MULTIPLE_ORIGINS = 'multiple-origins'

# Sentinel used to distinguish an explicit ``frame_options`` argument from the
# implicit SAMEORIGIN default.
_FRAME_OPTIONS_UNSET = object()

# X-Frame-Options values that are understood by browsers.
_FRAME_OPTIONS_CHOICES = (DENY, SAMEORIGIN, ALLOW_FROM)

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


class TalismanFramePolicyError(ValueError):
    """Raised when frame embedding policies cannot be reconciled.

    The message only names the category of embedding source involved; it never
    echoes a full origin or path.
    """


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
            frame_options=_FRAME_OPTIONS_UNSET,
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
                feature policy for the response.
            force_https: Redirects non-http requests to https, disabled in
                debug mode.
            force_https_permanent: Uses 301 instead of 302 redirects.
            frame_options: Sets the X-Frame-Options header, defaults to
                SAMEORIGIN. When the CSP contains a frame-ancestors
                directive, the two are reconciled so the emitted headers
                describe the same embedding sources; contradictory settings
                raise TalismanFramePolicyError.
            frame_options_allow_from: Used when frame_options is set to
                ALLOW_FROM and is a string of domains to allow frame
                embedding. ALLOW_FROM cannot silently coexist with a wider
                frame-ancestors policy.
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
        self.force_https = force_https
        self.force_https_permanent = force_https_permanent

        if frame_options is _FRAME_OPTIONS_UNSET:
            self.frame_options = SAMEORIGIN
            self.frame_options_explicit = False
        else:
            self.frame_options = frame_options
            self.frame_options_explicit = True
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

        # Reconcile the frame policy group at configuration time so that an
        # application which can never embed correctly fails fast instead of
        # emitting contradictory headers on every request.
        self._resolve_frame_policy(
            self.frame_options,
            self.frame_options_explicit,
            self.frame_options_allow_from,
            self.content_security_policy)
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
        if 'frame_options' in view_options:
            frame_options_explicit = True
            frame_options = view_options['frame_options']
        else:
            frame_options_explicit = self.frame_options_explicit
            frame_options = self.frame_options
        view_options['frame_options'] = frame_options
        view_options['frame_options_explicit'] = frame_options_explicit
        view_options.setdefault(
            'frame_options_allow_from', self.frame_options_allow_from)
        view_options.setdefault(
            'content_security_policy', self.content_security_policy)
        view_options.setdefault(
            'feature_policy', self.feature_policy
        )

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

    def _set_feature_headers(self, headers, options):
        if not options['feature_policy']:
            return

        policy = options['feature_policy']
        policy = self._parse_policy(policy)

        headers['Feature-Policy'] = policy

    def _frame_ancestors(self, content_security_policy):
        """Return the raw tokens of the CSP ``frame-ancestors`` directive.

        Returns ``None`` when the directive is absent and an empty list when
        it is present but carries no sources. Both dictionaries and pre-built
        policy strings are supported.
        """
        if not content_security_policy:
            return None

        if isinstance(content_security_policy, string_types):
            for policy_part in content_security_policy.split(';'):
                tokens = policy_part.strip().split()
                if tokens and tokens[0].lower() == 'frame-ancestors':
                    return tokens[1:]
            return None

        for directive, value in iteritems(content_security_policy):
            if directive.lower() == 'frame-ancestors':
                if isinstance(value, string_types):
                    tokens = value.split()
                else:
                    tokens = list(value)
                return tokens
        return None

    def _frame_ancestors_category(self, tokens):
        if not tokens:
            return FRAME_ANCESTORS_NONE
        if len(tokens) == 1:
            if tokens[0].lower() == "'none'":
                return FRAME_ANCESTORS_NONE
            if tokens[0].lower() == "'self'":
                return FRAME_ANCESTORS_SELF
            return FRAME_ANCESTORS_SINGLE_ORIGIN
        return FRAME_ANCESTORS_MULTIPLE_ORIGINS

    def _resolve_frame_policy(
            self, frame_options, frame_options_explicit,
            frame_options_allow_from, content_security_policy):
        """Normalize the frame policy group into a single source of truth.

        The CSP ``frame-ancestors`` directive and the ``X-Frame-Options``
        header must describe the same set of embedding sources whenever both
        are emitted. When a source set cannot be expressed with
        X-Frame-Options, the header is omitted (or an explicit contradiction
        raises). Returns a tuple of ``(xfo_value, audit)`` where ``xfo_value``
        is either ``None`` or the full X-Frame-Options header value and
        ``audit`` only records source categories.
        """
        if (frame_options is not None and
                frame_options not in _FRAME_OPTIONS_CHOICES):
            raise TalismanFramePolicyError(
                'frame_options must be one of DENY, SAMEORIGIN, ALLOW_FROM '
                'or None')

        tokens = self._frame_ancestors(content_security_policy)
        has_frame_ancestors = tokens is not None
        category = (
            self._frame_ancestors_category(tokens)
            if has_frame_ancestors else None)

        audit = {
            'frame_options': frame_options,
            'frame_options_explicit': frame_options_explicit,
            'frame_ancestors_category': category,
        }

        if not has_frame_ancestors:
            if frame_options == ALLOW_FROM and not frame_options_allow_from:
                raise TalismanFramePolicyError(
                    'frame_options ALLOW_FROM requires an allowed embedding '
                    'origin category')
            return self._build_xfo(frame_options, frame_options_allow_from), \
                audit

        if not frame_options_explicit:
            # Derive an explicit, equivalent X-Frame-Options policy when the
            # source set can be expressed, otherwise rely on CSP alone.
            if category == FRAME_ANCESTORS_NONE:
                frame_options = DENY
            elif category == FRAME_ANCESTORS_SELF:
                frame_options = SAMEORIGIN
            elif category == FRAME_ANCESTORS_SINGLE_ORIGIN:
                frame_options = ALLOW_FROM
                frame_options_allow_from = ' '.join(tokens)
            else:
                frame_options = None
            audit['frame_options'] = frame_options
            return self._build_xfo(frame_options, frame_options_allow_from), \
                audit

        if frame_options is None:
            # Explicitly suppressing X-Frame-Options cannot contradict the
            # CSP, which remains the sole frame embedding policy.
            return None, audit

        if category == FRAME_ANCESTORS_MULTIPLE_ORIGINS:
            raise TalismanFramePolicyError(
                'X-Frame-Options cannot express a multiple-origins '
                'frame-ancestors policy; set frame_options to None to rely '
                'on CSP exclusively')

        if category == FRAME_ANCESTORS_NONE:
            if frame_options == DENY:
                return self._build_xfo(DENY, None), audit
            raise TalismanFramePolicyError(
                'frame-ancestors denies all embedding but X-Frame-Options '
                'allows a frame-options category')

        if category == FRAME_ANCESTORS_SELF:
            if frame_options == SAMEORIGIN:
                return self._build_xfo(SAMEORIGIN, None), audit
            raise TalismanFramePolicyError(
                'frame-ancestors allows same-origin embedding but '
                'X-Frame-Options declares a different category')

        if frame_options != ALLOW_FROM:
            raise TalismanFramePolicyError(
                'a single-origin frame-ancestors policy requires '
                'X-Frame-Options ALLOW_FROM')
        if not frame_options_allow_from:
            raise TalismanFramePolicyError(
                'frame_options ALLOW_FROM requires an allowed embedding '
                'origin category')

        # ALLOW-FROM may only coexist with a frame-ancestors policy of the
        # same width; a wider CSP (self or multiple origins) must not be
        # silently narrowed by the legacy header.
        allow_from_tokens = frame_options_allow_from.split()
        allow_from_category = self._frame_ancestors_category(
            allow_from_tokens)
        if allow_from_category != FRAME_ANCESTORS_SINGLE_ORIGIN:
            raise TalismanFramePolicyError(
                'ALLOW_FROM may only coexist with a single-origin '
                'frame-ancestors policy')
        if ' '.join(allow_from_tokens) != ' '.join(tokens):
            raise TalismanFramePolicyError(
                'ALLOW_FROM origin category conflicts with the '
                'frame-ancestors origin category')

        return (
            self._build_xfo(ALLOW_FROM, frame_options_allow_from), audit)

    @staticmethod
    def _build_xfo(frame_options, frame_options_allow_from):
        if not frame_options:
            return None
        if frame_options == ALLOW_FROM:
            return '{} {}'.format(ALLOW_FROM, frame_options_allow_from)
        return frame_options

    def _set_frame_options_headers(self, headers, options):
        xfo_value, audit = self._resolve_frame_policy(
            options['frame_options'],
            options['frame_options_explicit'],
            options['frame_options_allow_from'],
            options['content_security_policy'])

        if xfo_value is not None:
            headers['X-Frame-Options'] = xfo_value

        flask.request.talisman_frame_audit = audit

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

        Only frame_options, frame_options_allow_from, and
        content_security_policy can be set on a per-view basis. The frame
        options and frame-ancestors directive of the view's CSP are merged
        into one frame policy group and reconciled together; overriding only
        one header never leaves the other in a contradictory state.

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
