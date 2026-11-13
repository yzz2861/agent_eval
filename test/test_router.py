# -*- coding: utf-8 -*-

import unittest
import bottle
import warnings


class TestRouter(unittest.TestCase):
    CGI = False
    
    def setUp(self):
        self.r = bottle.Router()
    
    def add(self, path, target, method='GET', **ka):
        with warnings.catch_warnings() as r:
            warnings.simplefilter("ignore")
            self.r.add(path, method, target, **ka)

    def match(self, path, method='GET'):
        env = {'PATH_INFO': path, 'REQUEST_METHOD': method}
        if self.CGI:
            env['wsgi.run_once'] = 'true'
        return self.r.match(env)

    def assertMatches(self, rule, url, method='GET', **args):
        self.add(rule, rule, method)
        target, urlargs = self.match(url, method)
        self.assertEqual(rule, target)
        self.assertEqual(args, urlargs)

    def testBasic(self):
        self.assertMatches('/static', '/static')
        self.assertMatches('/\\:its/:#.+#/:test/:name#[a-z]+#/',
                           '/:its/a/cruel/world/',
                           test='cruel', name='world')
        self.assertMatches('/:test', '/test', test='test') # No tail
        self.assertMatches(':test/', 'test/', test='test') # No head
        self.assertMatches('/:test/', '/test/', test='test') # Middle
        self.assertMatches(':test', 'test', test='test') # Full wildcard
        self.assertMatches('/:#anon#/match', '/anon/match') # Anon wildcards
        self.assertRaises(bottle.HTTPError, self.match, '//no/m/at/ch/')

    def testNewSyntax(self):
        self.assertMatches('/static', '/static')
        self.assertMatches('/\\<its>/<:re:.+>/<test>/<name:re:[a-z]+>/',
                           '/<its>/a/cruel/world/',
                           test='cruel', name='world')
        self.assertMatches('/<test>', '/test', test='test') # No tail
        self.assertMatches('<test>/', 'test/', test='test') # No head
        self.assertMatches('/<test>/', '/test/', test='test') # Middle
        self.assertMatches('<test>', 'test', test='test') # Full wildcard
        self.assertMatches('/<:re:anon>/match', '/anon/match') # Anon wildcards
        self.assertRaises(bottle.HTTPError, self.match, '//no/m/at/ch/')

    def testUnicode(self):
        self.assertMatches('/uni/<x>', '/uni/瓶', x='瓶')

    def testValueErrorInFilter(self):
        self.r.add_filter('test', lambda x: ('.*', int, int))

        self.assertMatches('/int/<i:test>', '/int/5', i=5) # No tail
        self.assertRaises(bottle.HTTPError, self.match, '/int/noint')

    def testIntFilter(self):
        self.assertMatches('/object/<id:int>', '/object/567', id=567)
        self.assertRaises(bottle.HTTPError, self.match, '/object/abc')

    def testFloatFilter(self):
        self.assertMatches('/object/<id:float>', '/object/1', id=1)
        self.assertMatches('/object/<id:float>', '/object/1.1', id=1.1)
        self.assertMatches('/object/<id:float>', '/object/.1', id=0.1)
        self.assertMatches('/object/<id:float>', '/object/1.', id=1)
        self.assertRaises(bottle.HTTPError, self.match, '/object/abc')
        self.assertRaises(bottle.HTTPError, self.match, '/object/')
        self.assertRaises(bottle.HTTPError, self.match, '/object/.')

    def testPathFilter(self):
        self.assertMatches('/<id:path>/:f', '/a/b', id='a', f='b')
        self.assertMatches('/<id:path>', '/a', id='a')

    def testAnonWildcard(self):
        self.assertMatches('/anon/<>', '/anon/whatever')
        self.assertMatches('/anonfilter/<:int>', '/anonfilter/5')
        self.assertRaises(bottle.HTTPError, self.match, '/anonfilter/noint')

    def testWildcardNames(self):
        self.assertMatches('/alpha/:abc', '/alpha/alpha', abc='alpha')
        self.assertMatches('/alnum/:md5', '/alnum/sha1', md5='sha1')

    def testParentheses(self):
        self.assertMatches('/func(:param)', '/func(foo)', param='foo')
        self.assertMatches('/func2(:param#(foo|bar)#)', '/func2(foo)', param='foo')
        self.assertMatches('/func2(:param#(foo|bar)#)', '/func2(bar)', param='bar')
        self.assertRaises(bottle.HTTPError, self.match, '/func2(baz)')

    def testErrorInPattern(self):
        self.assertRaises(Exception, self.assertMatches, '/:bug#(#/', '/foo/')
        self.assertRaises(Exception, self.assertMatches, '/<:re:(>/', '/foo/')

    def testBuild(self):
        add, build = self.add, self.r.build
        add('/:test/:name#[a-z]+#/', 'handler', name='testroute')

        url = build('testroute', test='hello', name='world')
        self.assertEqual('/hello/world/', url)

        url = build('testroute', test='hello', name='world', q='value')
        self.assertEqual('/hello/world/?q=value', url)

        # RouteBuildError: Missing URL argument: 'test'
        self.assertRaises(bottle.RouteBuildError, build, 'test')

    def testBuildAnon(self):
        add, build = self.add, self.r.build
        add('/anon/:#.#', 'handler', name='anonroute')

        url = build('anonroute', 'hello')
        self.assertEqual('/anon/hello', url)

        url = build('anonroute', 'hello', q='value')
        self.assertEqual('/anon/hello?q=value', url)

        # RouteBuildError: Missing URL argument: anon0.
        self.assertRaises(bottle.RouteBuildError, build, 'anonroute')

    def testBuildFilter(self):
        add, build = self.add, self.r.build
        add('/int/<:int>', 'handler', name='introute')

        url = build('introute', '5')
        self.assertEqual('/int/5', url)

        # RouteBuildError: Missing URL argument: anon0.
        self.assertRaises(ValueError, build, 'introute', 'hello')

    def test_dynamic_before_static_any(self):
        ''' Static ANY routes have lower priority than dynamic GET routes. '''
        self.add('/foo', 'foo', 'ANY')
        self.assertEqual(self.match('/foo')[0], 'foo')
        self.add('/<:>', 'bar', 'GET')
        self.assertEqual(self.match('/foo')[0], 'bar')

    def test_any_static_before_dynamic(self):
        ''' Static ANY routes have higher priority than dynamic ANY routes. '''
        self.add('/<:>', 'bar', 'ANY')
        self.assertEqual(self.match('/foo')[0], 'bar')
        self.add('/foo', 'foo', 'ANY')
        self.assertEqual(self.match('/foo')[0], 'foo')

    def test_dynamic_any_if_method_exists(self):
        ''' Check dynamic ANY routes if the matching method is known,
            but not matched.'''
        self.add('/bar<:>', 'bar', 'GET')
        self.assertEqual(self.match('/barx')[0], 'bar')
        self.add('/foo<:>', 'foo', 'ANY')
        self.assertEqual(self.match('/foox')[0], 'foo')

    def test_lots_of_routes(self):
        n = bottle.Router._MAX_GROUPS_PER_PATTERN+10
        for i in range(n):        
            self.add('/<:>/'+str(i), str(i), 'GET')
        self.assertEqual(self.match('/foo/'+str(n-1))[0], str(n-1))

class TestRouterInCGIMode(TestRouter):
    ''' Makes no sense since the default route does not optimize CGI anymore.'''
    CGI = True


class TestStrictRouter(unittest.TestCase):
    def setUp(self):
        self.r = bottle.Router(strict_paths=True)

    def add(self, path, target, method='GET'):
        self.r.add(path, method, target)

    def match(self, path, method='GET', **extra):
        env = {'PATH_INFO': path, 'REQUEST_METHOD': method}
        env.update(extra)
        return self.r.match(env)

    def assertRejected(self, path, method='GET'):
        self.assertRaises(bottle.HTTPError, self.match, path, method)

    def test_decodes_once_and_keeps_real_values(self):
        self.add('/uni/<name>', 'unicode')
        self.add('/files/<name:path>', 'path')
        self.assertEqual(('unicode', {'name': '瓶'}),
                         self.match('/uni/%E7%93%B6'))
        self.assertEqual(('path', {'name': 'a b/c'}),
                         self.match('/files/a%20b/c'))

    def test_static_and_dynamic_priority(self):
        self.add('/reports/<rest:path>', 'reports')
        self.add('/admin/export', 'admin')
        self.assertEqual('admin', self.match('/admin/export')[0])
        self.assertEqual(('reports', {'rest': 'a/b'}),
                         self.match('/reports/a/b'))

    def test_raw_path_is_the_strict_source(self):
        self.add('/admin/export', 'admin')
        self.assertEqual('admin', self.match(
            '/not/the/path',
            **{'bottle.raw_path': '/admin/export'})[0])

    def test_rejects_ambiguous_paths(self):
        for path in (
            '/reports/../admin/export',
            '/reports/./admin/export',
            '/reports/%2e%2e/admin/export',
            '/reports/%252e%252e/admin/export',
            '/reports%2fadmin/export',
            '/reports%5cadmin/export',
            '/reports\\admin/export',
            '//reports/admin/export',
            '/reports/%00admin',
            '/reports/%0dadmin',
            '/reports/%0aadmin',
            '/reports/%zzadmin',
            '/reports/%',
        ):
            self.assertRejected(path)

    def test_405_uses_normalized_path(self):
        self.add('/locked', 'locked', method='POST')
        self.assertRejected('/locked')
        try:
            self.match('/%6cocked')
        except bottle.HTTPError as error:
            self.assertEqual(405, error.status_code)
            self.assertIn('POST', error.headers['Allow'])
        else:
            self.fail('Expected HTTPError(405)')

    def test_path_length_limit(self):
        router = bottle.Router(strict_paths=True, max_path_length=8)
        router.add('/123456789', 'GET', 'too-long')
        self.assertRaises(
            bottle.HTTPError, router.match,
            {'PATH_INFO': '/123456789', 'REQUEST_METHOD': 'GET'})
