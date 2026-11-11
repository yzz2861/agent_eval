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

from __future__ import absolute_import

import threading
import unittest

import flask
from flask_talisman import ALLOW_FROM, DENY, NONCE_LENGTH, Talisman
from six import iteritems


HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


def hello_world():
    return 'Hello, world'


def with_nonce():
    return flask.render_template_string(
        '<script nonce="{{csp_nonce()}}"></script>'
    )


def with_nonce_stream():
    def generate():
        yield '<script nonce="{}"></script>'.format(
            flask.request.csp_nonce)

    return flask.Response(flask.stream_with_context(generate()))


def with_nonce_generator():
    yield '<script nonce="{}"></script>'.format(flask.request.csp_nonce)


def redirect_view():
    return flask.redirect('/')


def raise_error():
    flask.abort(500)


def conditional():
    response = flask.make_response('conditional content')
    response.set_etag('fixed-etag')
    return response.make_conditional(flask.request)


class TestTalismanExtension(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.talisman = Talisman(self.app)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)
        self.app.route('/with_nonce')(with_nonce)
        self.app.route('/with_nonce_stream')(with_nonce_stream)
        self.app.route('/with_nonce_generator')(with_nonce_generator)
        self.app.route('/redirect')(redirect_view)
        self.app.route('/error')(raise_error)
        self.app.route('/conditional')(conditional)

    def testDefaults(self):
        # HTTPS request.
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)

        headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'Strict-Transport-Security':
            'max-age=31556926; includeSubDomains',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'default-src \'self\'',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }

        for key, value in iteritems(headers):
            self.assertEqual(response.headers.get(key), value)

    def testForceSslOptionOptions(self):
        # HTTP request from Proxy
        response = self.client.get('/', headers={
            'X-Forwarded-Proto': 'https'
        })
        self.assertEqual(response.status_code, 200)

        # HTTP Request, should be upgraded to https
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('https://'))

        # Permanent redirects
        self.talisman.force_https_permanent = True
        response = self.client.get('/')
        self.assertEqual(response.status_code, 301)

        # Disable forced ssl, should allow the request.
        self.talisman.force_https = False
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testHstsOptions(self):
        self.talisman.force_ssl = False

        # No HSTS headers for non-ssl requests
        response = self.client.get('/')
        self.assertNotIn('Strict-Transport-Security', response.headers)

        # Secure request with HSTS off
        self.talisman.strict_transport_security = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('Strict-Transport-Security', response.headers)

        # HSTS back on
        self.talisman.strict_transport_security = True

        # HTTPS request through proxy
        response = self.client.get('/', headers={
            'X-Forwarded-Proto': 'https'
        })
        self.assertIn('Strict-Transport-Security', response.headers)

        # No subdomains
        self.talisman.strict_transport_security_include_subdomains = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn(
            'includeSubDomains', response.headers['Strict-Transport-Security'])

        # Preload
        self.talisman.strict_transport_security_preload = True
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('preload', response.headers['Strict-Transport-Security'])

    def testFrameOptions(self):
        self.talisman.frame_options = DENY
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')

        self.talisman.frame_options = ALLOW_FROM
        self.talisman.frame_options_allow_from = 'example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(
            response.headers['X-Frame-Options'], 'ALLOW-FROM example.com')

        self.talisman.frame_options = None
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('X-Frame-Options', response.headers)

    def testContentSecurityPolicyOptions(self):
        self.talisman.content_security_policy['image-src'] = '*'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertEqual(csp, "default-src 'self'; image-src *")

        self.talisman.content_security_policy['image-src'] = [
            '\'self\'',
            'example.com'
        ]
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertIn('default-src \'self\'', csp)
        self.assertIn('image-src \'self\' example.com', csp)

        # string policy
        self.talisman.content_security_policy = 'default-src \'foo\' spam.eggs'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['Content-Security-Policy'],
                         'default-src \'foo\' spam.eggs')

        # no policy
        self.talisman.content_security_policy = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('Content-Security-Policy', response.headers)

        # string policy at initialization
        app = flask.Flask(__name__)
        Talisman(app, content_security_policy='default-src \'foo\' spam.eggs')
        response = app.test_client().get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn(
            'default-src \'foo\' spam.eggs',
            response.headers['Content-Security-Policy']
        )

    def testContentSecurityPolicyOptionsReport(self):
        # report-only policy
        self.talisman.content_security_policy_report_only = True
        self.talisman.content_security_policy_report_uri = \
            'https://example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('Content-Security-Policy-Report-Only', response.headers)
        self.assertIn(
            'report-uri',
            response.headers['Content-Security-Policy-Report-Only']
        )
        self.assertNotIn('Content-Security-Policy', response.headers)

        override_report_uri = 'https://report-uri.io/'
        self.talisman.content_security_policy = {
            'report-uri': override_report_uri,
        }
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn(
            'Content-Security-Policy-Report-Only', response.headers)
        self.assertIn(
            override_report_uri,
            response.headers['Content-Security-Policy-Report-Only']
        )

        # exception on missing report-uri when report-only
        self.assertRaises(ValueError, Talisman, self.app,
                          content_security_policy_report_only=True)

    def testContentSecurityPolicyNonce(self):
        self.talisman.content_security_policy['script-src'] = "'self'"
        self.talisman.content_security_policy_nonce_in = ['script-src']

        with self.app.test_client() as client:
            response = client.get('/with_nonce',
                                  environ_overrides=HTTPS_ENVIRON)

            csp = response.headers['Content-Security-Policy']

            self.assertIn(
                "script-src 'self' 'nonce-{}'".format(flask.request.csp_nonce),
                csp
            )
            self.assertIn(
                flask.request.csp_nonce,
                response.data.decode("utf-8")
            )
            self.assertEqual(len(flask.request.csp_nonce), NONCE_LENGTH)

    def _enable_nonce(self, sections=('script-src',)):
        self.talisman.content_security_policy['script-src'] = "'self'"
        self.talisman.content_security_policy_nonce_in = list(sections)

    @staticmethod
    def _nonce_from_csp(csp):
        prefix = "'nonce-"
        start = csp.index(prefix) + len(prefix)
        end = csp.index("'", start)
        return csp[start:end]

    @staticmethod
    def _nonce_from_body(body):
        prefix = 'nonce="'
        start = body.index(prefix) + len(prefix)
        end = body.index('"', start)
        return body[start:end]

    def testNonceHeaderMatchesTemplate(self):
        self._enable_nonce()

        response = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)

        header_nonce = self._nonce_from_csp(
            response.headers['Content-Security-Policy'])
        body_nonce = self._nonce_from_body(response.data.decode('utf-8'))
        self.assertEqual(header_nonce, body_nonce)
        self.assertEqual(len(header_nonce), NONCE_LENGTH)

    def testNonceIsUniquePerRequest(self):
        self._enable_nonce()

        first = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)
        second = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)

        self.assertNotEqual(
            self._nonce_from_csp(first.headers['Content-Security-Policy']),
            self._nonce_from_csp(second.headers['Content-Security-Policy'])
        )
        self.assertNotEqual(
            self._nonce_from_body(first.data.decode('utf-8')),
            self._nonce_from_body(second.data.decode('utf-8'))
        )

    def testStreamingResponseNonce(self):
        self._enable_nonce()

        response = self.client.get(
            '/with_nonce_stream', environ_overrides=HTTPS_ENVIRON)

        # The header is finalized before the generator is iterated and
        # carries the same nonce as the streamed body.
        header_nonce = self._nonce_from_csp(
            response.headers['Content-Security-Policy'])
        body = b''.join(response.response).decode('utf-8')
        self.assertEqual(header_nonce, self._nonce_from_body(body))

    def testGeneratorResponseNonce(self):
        self._enable_nonce()

        # A view returning a bare generator is wrapped by Flask itself;
        # the nonce must still be finalized before the header is sent.
        response = self.client.get(
            '/with_nonce_generator', environ_overrides=HTTPS_ENVIRON)

        header_nonce = self._nonce_from_csp(
            response.headers['Content-Security-Policy'])
        body = b''.join(response.response).decode('utf-8')
        self.assertEqual(header_nonce, self._nonce_from_body(body))

    def testNoNonceForUnconfiguredSection(self):
        self.talisman.content_security_policy['script-src'] = "'self'"
        self.talisman.content_security_policy_nonce_in = ['style-src']

        response = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)

        # A section that is not part of the policy never gets a nonce,
        # even though a request nonce may still be available to templates.
        self.assertNotIn(
            'nonce-', response.headers['Content-Security-Policy'])
        self.assertNotIn('nonce-', response.data.decode('utf-8'))

    def testNoNonceWhenCspDisabled(self):
        self._enable_nonce()
        self.talisman.content_security_policy = False

        response = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)

        self.assertNotIn('Content-Security-Policy', response.headers)
        self.assertIn('nonce=""', response.data.decode('utf-8'))

    def testNoNonceWhenRouteDisablesCsp(self):
        self._enable_nonce()

        @self.app.route('/route_no_csp')
        @self.talisman(content_security_policy=None)
        def route_no_csp():
            return flask.render_template_string(
                '<script nonce="{{csp_nonce()}}"></script>'
            )

        response = self.client.get(
            '/route_no_csp', environ_overrides=HTTPS_ENVIRON)

        self.assertNotIn('Content-Security-Policy', response.headers)
        self.assertIn('nonce=""', response.data.decode('utf-8'))

    def testReportOnlyHeaderUsesSameNonce(self):
        self._enable_nonce()
        self.talisman.content_security_policy_report_only = True
        self.talisman.content_security_policy_report_uri = \
            'https://example.com'

        response = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)

        header_nonce = self._nonce_from_csp(
            response.headers['Content-Security-Policy-Report-Only'])
        body_nonce = self._nonce_from_body(response.data.decode('utf-8'))
        self.assertEqual(header_nonce, body_nonce)
        self.assertNotIn('Content-Security-Policy', response.headers)

    def testNonceOnRedirectResponse(self):
        self._enable_nonce()

        response = self.client.get(
            '/redirect', environ_overrides=HTTPS_ENVIRON)

        self.assertEqual(response.status_code, 302)
        header_nonce = self._nonce_from_csp(
            response.headers['Content-Security-Policy'])
        self.assertEqual(len(header_nonce), NONCE_LENGTH)

        # A following request must not reuse the redirect's nonce.
        follow_up = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)
        self.assertNotEqual(
            header_nonce,
            self._nonce_from_csp(follow_up.headers['Content-Security-Policy'])
        )

    def testNoNonceOnForceHttpsRedirect(self):
        self._enable_nonce()

        # The redirect response never exposes a nonce, and the next
        # request gets a fresh value rather than a reused one.
        response = self.client.get('/with_nonce')

        self.assertEqual(response.status_code, 302)
        self.assertNotIn(
            'nonce-', response.headers['Content-Security-Policy'])

        follow_up = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)
        self.assertIn(
            'nonce-', follow_up.headers['Content-Security-Policy'])

    def testNonceOnNotModifiedResponse(self):
        self._enable_nonce()

        first = self.client.get(
            '/conditional', environ_overrides=HTTPS_ENVIRON)
        etag = first.headers['ETag']
        not_modified = self.client.get(
            '/conditional',
            headers={'If-None-Match': etag},
            environ_overrides=HTTPS_ENVIRON)

        self.assertEqual(not_modified.status_code, 304)
        header_nonce = self._nonce_from_csp(
            not_modified.headers['Content-Security-Policy'])
        self.assertEqual(len(header_nonce), NONCE_LENGTH)

        # Each conditional request gets its own nonce; a previous request's
        # value is never reused.
        second_not_modified = self.client.get(
            '/conditional',
            headers={'If-None-Match': etag},
            environ_overrides=HTTPS_ENVIRON)
        self.assertNotEqual(
            header_nonce,
            self._nonce_from_csp(
                second_not_modified.headers['Content-Security-Policy'])
        )

    def testNonceOnErrorResponse(self):
        self._enable_nonce()

        response = self.client.get(
            '/error', environ_overrides=HTTPS_ENVIRON)

        self.assertEqual(response.status_code, 500)
        header_nonce = self._nonce_from_csp(
            response.headers['Content-Security-Policy'])
        self.assertEqual(len(header_nonce), NONCE_LENGTH)

    def testBlueprintOverrideDisablesCspAndNonce(self):
        self._enable_nonce()
        blueprint = flask.Blueprint('no_csp_bp', __name__)

        @blueprint.route('/bp')
        def bp_view():
            return flask.render_template_string(
                '<script nonce="{{csp_nonce()}}"></script>'
            )

        self.app.register_blueprint(
            self.talisman(content_security_policy=None)(blueprint))

        response = self.client.get('/bp', environ_overrides=HTTPS_ENVIRON)

        self.assertNotIn('Content-Security-Policy', response.headers)
        self.assertIn('nonce=""', response.data.decode('utf-8'))

        # Other requests keep their own CSP and nonce behaviour.
        unaffected = self.client.get(
            '/with_nonce', environ_overrides=HTTPS_ENVIRON)
        self.assertIn(
            'nonce-', unaffected.headers['Content-Security-Policy'])

    def testBlueprintOverrideCspPolicy(self):
        self._enable_nonce()
        blueprint = flask.Blueprint('custom_csp_bp', __name__)

        @blueprint.route('/bp')
        def bp_view():
            return 'Hello, world'

        self.app.register_blueprint(
            self.talisman(
                content_security_policy={'default-src': "'none'"}
            )(blueprint)
        )

        response = self.client.get('/bp', environ_overrides=HTTPS_ENVIRON)

        self.assertEqual(
            response.headers['Content-Security-Policy'],
            "default-src 'none'")

    def testConcurrentRequestsHaveIsolatedNonces(self):
        self._enable_nonce()
        results = []

        def make_request():
            with self.app.test_client() as client:
                response = client.get(
                    '/with_nonce_stream',
                    environ_overrides=HTTPS_ENVIRON)
                nonce = self._nonce_from_csp(
                    response.headers['Content-Security-Policy'])
                body = b''.join(response.response).decode('utf-8')
                results.append((nonce, self._nonce_from_body(body)))

        threads = [threading.Thread(target=make_request) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), len(threads))
        header_nonces = [header_nonce for header_nonce, _ in results]
        self.assertEqual(len(set(header_nonces)), len(threads))
        for header_nonce, body_nonce in results:
            self.assertEqual(header_nonce, body_nonce)

    def testDecorator(self):
        @self.app.route('/nocsp')
        @self.talisman(content_security_policy=None)
        def nocsp():
            return 'Hello, world'

        response = self.client.get('/nocsp', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('Content-Security-Policy', response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'SAMEORIGIN')

    def testDecoratorForceHttps(self):
        @self.app.route('/noforcehttps')
        @self.talisman(force_https=False)
        def noforcehttps():
            return 'Hello, world'

        response = self.client.get('/noforcehttps')
        self.assertEqual(response.status_code, 200)

    def testForceFileSave(self):
        self.talisman.force_file_save = True
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('X-Download-Options', response.headers)
        self.assertEqual(response.headers['X-Download-Options'], 'noopen')

    def testBadEndpoint(self):
        response = self.client.get('/bad_endpoint')
        self.assertEqual(response.status_code, 302)
        response = self.client.get('/bad_endpoint',
                                   headers={'X-Forwarded-Proto': 'https'})
        self.assertEqual(response.status_code, 404)

    def testFeaturePolicy(self):
        self.talisman.feature_policy['geolocation'] = '\'none\''
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        feature_policy = response.headers['Feature-Policy']
        self.assertIn('geolocation \'none\'', feature_policy)

        self.talisman.feature_policy['fullscreen'] = '\'self\' example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        feature_policy = response.headers['Feature-Policy']
        self.assertIn('fullscreen \'self\' example.com', feature_policy)

        # string policy at initialization
        app = flask.Flask(__name__)
        Talisman(app, feature_policy='vibrate \'none\'')
        response = app.test_client().get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('vibrate \'none\'', response.headers['Feature-Policy'])
