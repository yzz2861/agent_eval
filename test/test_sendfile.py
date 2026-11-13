import sys
import unittest
from bottle import static_file, request, response, parse_date, parse_range_header, Bottle, tob
import bottle
import wsgiref.util
import os
import tempfile
import time

basename = os.path.basename(__file__)
root = os.path.dirname(__file__)

basename2 = os.path.basename(bottle.__file__)
root2 = os.path.dirname(bottle.__file__)


weekday_full = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
weekday_abbr = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
month_abbr = [None, 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

class TestDateParser(unittest.TestCase):
    def test_rfc1123(self):
        """DateParser: RFC 1123 format"""
        ts = time.time()
        rs = bottle.http_date(ts)
        self.assertEqual(int(ts), int(parse_date(rs)))

    def test_rfc850(self):
        """DateParser: RFC 850 format"""
        ts = time.time()
        t = time.gmtime(ts)
        rs = time.strftime("%%s, %d-%%s-%y %H:%M:%S GMT", t) % (weekday_full[t.tm_wday], month_abbr[t.tm_mon])
        self.assertEqual(int(ts), int(parse_date(rs)))

    def test_asctime(self):
        """DateParser: asctime format"""
        ts = time.time()
        t = time.gmtime(ts)
        rs = time.strftime("%%s %%s %d %H:%M:%S %Y", t) % (weekday_abbr[t.tm_wday], month_abbr[t.tm_mon])
        self.assertEqual(int(ts), int(parse_date(rs)))

    def test_bad(self):
        """DateParser: Bad format"""
        self.assertEqual(None, parse_date('Bad 123'))


class TestSendFile(unittest.TestCase):
    def setUp(self):
        e = dict()
        wsgiref.util.setup_testing_defaults(e)
        b = Bottle()
        request.bind(e)
        response.bind()

    def test_valid(self):
        """ SendFile: Valid requests"""
        out = static_file(basename, root=root)
        self.assertEqual(open(__file__,'rb').read(), out.body.read())

    def test_invalid(self):
        """ SendFile: Invalid requests"""
        self.assertEqual(404, static_file('not/a/file', root=root).status_code)
        f = static_file(os.path.join('./../', basename), root='./views/')
        self.assertEqual(403, f.status_code)

    def test_file_not_readable(self):
        if sys.platform == 'win32':
            return
        if os.geteuid() == 0:
            return # Root can read anything

        try:
            fp, fn = tempfile.mkstemp()
            os.chmod(fn, 0)
            self.assertEqual(403, static_file(fn, root='/').status_code)
        finally:
            os.close(fp)
            os.unlink(fn)

    def test_mime(self):
        """ SendFile: Mime Guessing"""
        f = static_file(basename, root=root)
        self.assertTrue(f.headers['Content-Type'].split(';')[0] in ('application/x-python-code', 'text/x-python'))
        f = static_file(basename, root=root, mimetype='some/type')
        self.assertEqual('some/type', f.headers['Content-Type'])
        f = static_file(basename, root=root, mimetype='text/foo')
        self.assertEqual('text/foo; charset=UTF-8', f.headers['Content-Type'])
        f = static_file(basename, root=root, mimetype='text/foo', charset='latin1')
        self.assertEqual('text/foo; charset=latin1', f.headers['Content-Type'])

    def test_mime_gzip(self):
        """ SendFile: Mime Guessing"""
        try:
            fp, fn = tempfile.mkstemp(suffix=".txt.gz")
            os.close(fp) #  File needs to be closed before it can be accessed on Windows
            f = static_file(fn, root='/')
            self.assertTrue(f.headers['Content-Type'][0] in ('application/gzip'))
            self.assertFalse('Content-Encoding' in f.headers)
        finally:
            os.close(fp)
            os.unlink(fn)

    def test_ims(self):
        """ SendFile: If-Modified-Since"""
        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(time.time())
        res = static_file(basename, root=root)
        self.assertEqual(304, res.status_code)
        self.assertEqual(int(os.stat(__file__).st_mtime), parse_date(res.headers['Last-Modified']))
        self.assertAlmostEqual(int(time.time()), parse_date(res.headers['Date']), delta=2)
        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(100)
        self.assertEqual(open(__file__,'rb').read(), static_file(basename, root=root).body.read())

    def test_ims_empty(self):
        """ SendFile: Empty If-Modified-Since"""
        request.environ['HTTP_IF_MODIFIED_SINCE'] = ''
        self.assertEqual(open(__file__, 'rb').read(), static_file(basename, root=root).body.read())

    def test_etag(self):
        """ SendFile: If-None-Match"""
        res = static_file(basename, root=root)
        self.assertTrue('ETag' in res.headers)
        self.assertEqual(200, res.status_code)
        etag = res.headers['ETag']

        # Known and matching etag should return 304
        request.environ['HTTP_IF_NONE_MATCH'] = etag
        res = static_file(basename, root=root)
        self.assertEqual(etag, res.headers.get('ETag'))
        self.assertEqual(304, res.status_code)

        # The INM header can be multi-valued
        request.environ['HTTP_IF_NONE_MATCH'] = '"multi", "valued", ' + etag
        self.assertEqual(etag, res.headers.get('ETag'))
        self.assertEqual(304, static_file(basename, root=root).status_code)

        # Non-matching etag
        request.environ['HTTP_IF_NONE_MATCH'] = '"BadEtag"'
        res = static_file(basename, root=root)
        self.assertEqual(etag, res.headers.get('ETag'))
        self.assertEqual(200, res.status_code)

        # Unquoted (invalid) etag
        request.environ['HTTP_IF_NONE_MATCH'] = etag.strip('"')
        res = static_file(basename, root=root)
        self.assertEqual(etag, res.headers.get('ETag'))
        self.assertEqual(200, res.status_code)

        # Etag for different file etag
        request.environ['HTTP_IF_NONE_MATCH'] = etag
        res = static_file(basename2, root=root2)
        self.assertNotEqual(etag, res.headers.get('ETag'))
        self.assertEqual(200, res.status_code)

    def test_etag_overrides_ims(self):
        """ RFC 7232 sec 3.3: If-Modified-Since MUST be ignored whenever
        If-None-Match is present in the request. """

        # If-Modified-Since would return 304 but If-None-Match should
        # override and prevent that.
        request.environ['HTTP_IF_NONE_MATCH'] = '"no-match"'
        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(time.time())
        res = static_file(basename, root=root)
        self.assertEqual(200, res.status_code)

        # If-Modified-Since would return 200 but If-None-Match should
        # override and prevent that.
        request.environ['HTTP_IF_NONE_MATCH'] = res.headers['ETag']
        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(100)
        res = static_file(basename, root=root)
        self.assertEqual(304, res.status_code)

    def test_download(self):
        """ SendFile: Download as attachment """
        f = static_file(basename, root=root, download="foo.mp3")
        self.assertEqual('audio/mpeg', f.headers['Content-Type'])

        f = static_file(basename, root=root, download=True)
        self.assertEqual('attachment; filename="%s"' % basename, f.headers['Content-Disposition'])
        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(100)

        f = static_file(basename, root=root)
        self.assertEqual(open(__file__,'rb').read(), f.body.read())

    def test_range(self):
        request.environ['HTTP_RANGE'] = 'bytes=10-25,-80'
        f = static_file(basename, root=root)
        c = open(__file__, 'rb'); c.seek(10)
        self.assertEqual(c.read(16), tob('').join(f.body))
        self.assertEqual('bytes 10-25/%d' % len(open(__file__, 'rb').read()),
                         f.headers['Content-Range'])
        self.assertEqual('bytes', f.headers['Accept-Ranges'])

    def test_range_parser(self):
        r = lambda rs: list(parse_range_header(rs, 100))
        self.assertEqual([(90, 100)], r('bytes=-10'))
        self.assertEqual([(10, 100)], r('bytes=10-'))
        self.assertEqual([(5, 11)],  r('bytes=5-10'))
        self.assertEqual([(10, 100), (90, 100), (5, 11)],  r('bytes=10-,-10,5-10'))

    def test_custom_headers(self):
        """ SendFile: Custom headers """
        headers = {'X-Custom-Header': 'test-value'}
        headers_orig = headers.copy()
        res = static_file(basename, root=root, headers=headers)
        self.assertTrue('X-Custom-Header' in res.headers)
        self.assertEqual('test-value', res.headers['X-Custom-Header'])
        # Check the passed in headers dict isn't modified.
        self.assertEqual(headers_orig, headers)


class TestStrictStaticFile(unittest.TestCase):
    """ Strict path validation, Range hardening and entity consistency. """

    def setUp(self):
        e = dict()
        wsgiref.util.setup_testing_defaults(e)
        request.bind(e)
        response.bind()
        self.tmp = tempfile.mkdtemp()
        # A "public" root served by static_file()
        self.pub = os.path.join(self.tmp, 'public')
        os.mkdir(self.pub)
        os.mkdir(os.path.join(self.pub, 'sub'))
        self.data = b'0123456789abcdef'  # 16 bytes
        self.target = os.path.join(self.pub, 'sub', 'data.bin')
        with open(self.target, 'wb') as fp:
            fp.write(self.data)
        with open(os.path.join(self.pub, 'empty.bin'), 'wb'):
            pass
        # A shared, sensitive directory outside of the public root
        self.shared = os.path.join(self.tmp, 'certs')
        os.mkdir(self.shared)
        with open(os.path.join(self.shared, 'server.key'), 'wb') as fp:
            fp.write(b'PRIVATE-KEY-MATERIAL')
        # Symlink staying inside the root
        os.symlink(self.target, os.path.join(self.pub, 'good_link.bin'))
        # Symlink pointing at the shared cert directory
        os.symlink(self.shared, os.path.join(self.pub, 'evil_link'))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def _serve(self, filename, **kwargs):
        return static_file(filename, root=self.pub, strict=True, **kwargs)

    def test_normal_file_strict(self):
        """ Strict: ordinary root files keep working. """
        out = self._serve('sub/data.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_symlink_inside_root(self):
        """ Strict: symlinks resolving inside the root are followed. """
        out = self._serve('good_link.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_symlink_outside_root(self):
        """ Strict: a link to a shared folder outside the root is refused. """
        out = self._serve('evil_link/server.key')
        self.assertEqual(403, out.status_code)
        self.assertNotIn(b'PRIVATE', out.body if isinstance(out.body, bytes) else b'')

    def test_symlink_outside_root_default_mode(self):
        """ Default mode stays backwards compatible for in-root links. """
        out = static_file('good_link.bin', root=self.pub)
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_encoded_separator(self):
        """ Strict: percent encoded separators are decoded before joining. """
        out = self._serve('sub%2Fdata.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())
        out = self._serve('sub%5Cdata.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_encoded_traversal(self):
        """ Strict: encoded traversal cannot reach files outside the root. """
        out = self._serve('sub%2F..%2Fevil_link%2Fserver.key')
        self.assertEqual(403, out.status_code)
        out = self._serve('..%2Fcerts%2Fserver.key')
        self.assertEqual(403, out.status_code)
        out = self._serve('%2e%2e%2fcerts%2fserver.key')
        self.assertEqual(403, out.status_code)

    def test_alternate_separator(self):
        """ Strict: backslashes are treated as path separators. """
        out = self._serve('sub\\data.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_trailing_dot_component(self):
        """ Strict: trailing dots on a component are normalized away. """
        out = self._serve('sub./data.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_dotdot_coming_back_inside(self):
        """ Strict: a '..' path that resolves back inside the root works. """
        out = self._serve('sub/../sub/data.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual(self.data, out.body.read())

    def test_error_does_not_leak_paths(self):
        """ Strict: error responses never expose paths or link targets. """
        out = self._serve('evil_link/server.key')
        text = str(out.body)
        self.assertNotIn(self.tmp, text)
        self.assertNotIn('server.key', text)
        self.assertNotIn('certs', text)

    def test_missing_file_inside_root_is_404(self):
        """ Strict: a missing in-root file is 404, an escape stays 403. """
        self.assertEqual(404, self._serve('does_not_exist.bin').status_code)
        self.assertEqual(404, self._serve('sub/missing.bin').status_code)
        self.assertEqual(403, self._serve('../certs/server.key').status_code)

    def test_range_basic_open_and_suffix(self):
        """ Range: open and suffix ranges keep their documented semantics. """
        request.environ['HTTP_RANGE'] = 'bytes=4-'
        out = self._serve('sub/data.bin')
        self.assertEqual(206, out.status_code)
        self.assertEqual(self.data[4:], tob('').join(out.body))
        self.assertEqual('bytes 4-15/16', out.headers['Content-Range'])
        self.assertEqual('12', out.headers['Content-Length'])

        request.environ['HTTP_RANGE'] = 'bytes=-4'
        out = self._serve('sub/data.bin')
        self.assertEqual(206, out.status_code)
        self.assertEqual(self.data[-4:], tob('').join(out.body))
        self.assertEqual('bytes 12-15/16', out.headers['Content-Range'])

    def test_range_suffix_larger_than_file(self):
        """ Range: a suffix larger than the file returns the whole entity. """
        request.environ['HTTP_RANGE'] = 'bytes=-1000'
        out = self._serve('sub/data.bin')
        self.assertEqual(206, out.status_code)
        self.assertEqual(self.data, tob('').join(out.body))
        self.assertEqual('bytes 0-15/16', out.headers['Content-Range'])

    def test_range_unsupported_unit(self):
        """ Range: only the bytes unit is accepted. """
        request.environ['HTTP_RANGE'] = 'items=0-10'
        out = self._serve('sub/data.bin')
        self.assertEqual(416, out.status_code)
        self.assertEqual('bytes */16', out.headers['Content-Range'])

    def test_range_reversed(self):
        """ Range: reversed start/end is a deterministic 416, not an empty 200. """
        request.environ['HTTP_RANGE'] = 'bytes=10-5'
        out = self._serve('sub/data.bin')
        self.assertEqual(416, out.status_code)
        request.environ['HTTP_RANGE'] = 'bytes=999999999999-1'
        out = self._serve('sub/data.bin')
        self.assertEqual(416, out.status_code)

    def test_range_overlapping(self):
        """ Range: overlapping ranges are rejected with 416. """
        request.environ['HTTP_RANGE'] = 'bytes=0-10,5-15'
        out = self._serve('sub/data.bin')
        self.assertEqual(416, out.status_code)

    def test_range_too_many(self):
        """ Range: the number of ranges is bounded. """
        request.environ['HTTP_RANGE'] = 'bytes=' + ','.join(
            '%d-%d' % (i, i) for i in range(bottle.MAX_RANGE_REQUESTS + 1))
        out = self._serve('sub/data.bin')
        self.assertEqual(416, out.status_code)

    def test_range_malformed(self):
        """ Range: malformed specs are rejected with 416. """
        for spec in ('bytes=', 'bytes=-', 'bytes=abc', 'bytes=1-2-3',
                     'bytes= , '):
            request.environ['HTTP_RANGE'] = spec
            out = self._serve('sub/data.bin')
            self.assertEqual(416, out.status_code, spec)

    def test_range_end_beyond_file(self):
        """ Range: an end beyond the file is clamped to the file length. """
        request.environ['HTTP_RANGE'] = 'bytes=0-100000'
        out = self._serve('sub/data.bin')
        self.assertEqual(206, out.status_code)
        self.assertEqual(self.data, tob('').join(out.body))
        self.assertEqual('bytes 0-15/16', out.headers['Content-Range'])

    def test_range_empty_file(self):
        """ Range: any range on an empty file is unsatisfiable. """
        out = self._serve('empty.bin')
        self.assertEqual(200, out.status_code)
        self.assertEqual('0', out.headers['Content-Length'])
        request.environ['HTTP_RANGE'] = 'bytes=0-'
        out = self._serve('empty.bin')
        self.assertEqual(416, out.status_code)
        self.assertEqual('bytes */0', out.headers['Content-Range'])

    def test_etag_same_for_ranges(self):
        """ Range: every fragment carries the entity ETag and revalidates. """
        plain = self._serve('sub/data.bin')
        etag = plain.headers['ETag']
        last_modified = plain.headers['Last-Modified']

        for spec, slc in (('bytes=0-3', slice(0, 4)),
                          ('bytes=4-', slice(4, 16)),
                          ('bytes=-4', slice(12, 16))):
            request.environ['HTTP_RANGE'] = spec
            out = self._serve('sub/data.bin')
            self.assertEqual(206, out.status_code, spec)
            # Headers describe one single entity
            self.assertEqual(etag, out.headers['ETag'], spec)
            self.assertEqual(last_modified, out.headers['Last-Modified'], spec)
            # The served fragment must be reproducible from the file bytes
            self.assertEqual(self.data[slc], tob('').join(out.body), spec)
            start, end = slc.start or 0, (slc.stop or 16) - 1
            self.assertEqual('bytes %d-%d/16' % (start, end),
                             out.headers['Content-Range'], spec)

            # The same ETag revalidates the fragment against the entity
            request.environ['HTTP_IF_NONE_MATCH'] = etag
            reval = self._serve('sub/data.bin')
            self.assertEqual(304, reval.status_code, spec)
            del request.environ['HTTP_IF_NONE_MATCH']

    def test_etag_conflict(self):
        """ Range: ETags of two distinct files differ. """
        other = os.path.join(self.pub, 'other.bin')
        with open(other, 'wb') as fp:
            fp.write(b'totally different content bytes here!!')
        first = self._serve('sub/data.bin').headers['ETag']
        second = self._serve('other.bin').headers['ETag']
        self.assertNotEqual(first, second)
        request.environ['HTTP_IF_NONE_MATCH'] = first
        out = self._serve('other.bin')
        self.assertEqual(200, out.status_code)

    def test_etag_disabled(self):
        """ Range: etag=False suppresses ETag handling. """
        out = self._serve('sub/data.bin', etag=False)
        self.assertNotIn('ETag', out.headers)

    def test_ims_with_range(self):
        """ Range: IMS still describes the same entity for a fragment. """
        mtime = os.stat(self.target).st_mtime
        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(mtime + 10)
        request.environ['HTTP_RANGE'] = 'bytes=2-5'
        out = self._serve('sub/data.bin')
        self.assertEqual(304, out.status_code)
        self.assertNotIn('Content-Range', out.headers)

        request.environ['HTTP_IF_MODIFIED_SINCE'] = bottle.http_date(0)
        out = self._serve('sub/data.bin')
        self.assertEqual(206, out.status_code)
        self.assertEqual(self.data[2:6], tob('').join(out.body))
        self.assertEqual('bytes 2-5/16', out.headers['Content-Range'])

    def test_download_semicolon(self):
        """ Download: semicolons cannot truncate the filename parameter. """
        out = self._serve('sub/data.bin', download='report;final.bin')
        header = out.headers['Content-Disposition']
        self.assertEqual('attachment; filename="report_final.bin"', header)

    def test_download_chinese_name(self):
        """ Download: non-ASCII names use an RFC 5987 filename* parameter. """
        name = '\u62a5\u544a.bin'  # 报告.bin
        out = self._serve('sub/data.bin', download=name)
        header = out.headers['Content-Disposition']
        self.assertTrue(header.startswith('attachment; filename='))
        self.assertIn("filename*=UTF-8''", header)
        self.assertIn('%E6%8A%A5%E5%91%8A', header)

    def test_download_quote_neutralized(self):
        """ Download: quotes are removed so the header cannot be broken. """
        out = self._serve('sub/data.bin', download='na"me.bin')
        self.assertEqual('attachment; filename="name.bin"',
                         out.headers['Content-Disposition'])
