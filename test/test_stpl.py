# -*- coding: utf-8 -*-
from __future__ import with_statement
import unittest
from bottle import SimpleTemplate, TemplateError, view, template, touni, tob, html_quote
import re, os
import traceback
from textwrap import dedent
from .tools import chdir


class TestSimpleTemplate(unittest.TestCase):
    def assertRenders(self, tpl, to, *args, **vars):
        if isinstance(tpl, str):
            tpl = SimpleTemplate(tpl, lookup=[os.path.join(os.path.dirname(__file__), 'views')])
        self.assertEqual(touni(to), tpl.render(*args, **vars))

    def test_string(self):
        """ Templates: Parse string"""
        self.assertRenders('start {{var}} end', 'start var end', var='var')

    def test_self_as_variable_name(self):
        self.assertRenders('start {{self}} end', 'start var end', {'self':'var'})

    def test_file(self):
        with chdir(__file__):
            t = SimpleTemplate(name='./views/stpl_simple.tpl', lookup=['.'])
            self.assertRenders(t, 'start var end\n', var='var')

    def test_name(self):
        with chdir(__file__):
            t = SimpleTemplate(name='stpl_simple', lookup=['./views/'])
            self.assertRenders(t, 'start var end\n', var='var')

    def test_unicode(self):
        self.assertRenders('start {{var}} end', 'start äöü end', var=touni('äöü'))
        self.assertRenders('start {{var}} end', 'start äöü end', var=tob('äöü'))

    def test_unicode_code(self):
        """ Templates: utf8 code in file"""
        with chdir(__file__):
            t = SimpleTemplate(name='./views/stpl_unicode.tpl', lookup=['.'])
            self.assertRenders(t, 'start ñç äöü end\n', var=touni('äöü'))

    def test_import(self):
        """ Templates: import statement"""
        t = '%from base64 import b64encode\nstart {{b64encode(var.encode("ascii") if hasattr(var, "encode") else var)}} end'
        self.assertRenders(t, 'start dmFy end', var='var')

    def test_data(self):
        """ Templates: Data representation """
        t = SimpleTemplate('<{{var}}>')
        self.assertRenders('<{{var}}>', '<True>', var=True)
        self.assertRenders('<{{var}}>', '<False>', var=False)
        self.assertRenders('<{{var}}>', '<>', var=None)
        self.assertRenders('<{{var}}>', '<0>', var=0)
        self.assertRenders('<{{var}}>', '<5>', var=5)
        self.assertRenders('<{{var}}>', '<b>', var=tob('b'))
        self.assertRenders('<{{var}}>', '<1.0>', var=1.0)
        self.assertRenders('<{{var}}>', '<[1, 2]>', var=[1,2])

    def test_htmlutils_quote(self):
        self.assertEqual('"&lt;&#039;&#13;&#10;&#9;&quot;\\&gt;"', html_quote('<\'\r\n\t"\\>'));

    def test_escape(self):
        self.assertRenders('<{{var}}>', '<b>', var='b')
        self.assertRenders('<{{var}}>', '<&lt;&amp;&gt;>',var='<&>')

    def test_noescape(self):
        self.assertRenders('<{{!var}}>', '<b>',   var='b')
        self.assertRenders('<{{!var}}>', '<<&>>', var='<&>')

    def test_noescape_setting(self):
        t = SimpleTemplate('<{{var}}>', noescape=True)
        self.assertRenders(t, '<b>', var='b')
        self.assertRenders(t, '<<&>>', var='<&>')
        t = SimpleTemplate('<{{!var}}>', noescape=True)
        self.assertRenders(t, '<b>', var='b')
        self.assertRenders(t, '<&lt;&amp;&gt;>', var='<&>')

    def test_blocks(self):
        """ Templates: Code blocks and loops """
        t = "start\n%for i in l:\n{{i}} \n%end\nend"
        self.assertRenders(t, 'start\n1 \n2 \n3 \nend', l=[1,2,3])
        self.assertRenders(t, 'start\nend', l=[])
        t = "start\n%if i:\n{{i}} \n%end\nend"
        self.assertRenders(t, 'start\nTrue \nend', i=True)
        self.assertRenders(t, 'start\nend', i=False)

    def test_elsebug(self):
        ''' Whirespace between block keyword and colon is allowed '''
        self.assertRenders("%if 1:\nyes\n%else:\nno\n%end\n", "yes\n")
        self.assertRenders("%if 1:\nyes\n%else     :\nno\n%end\n", "yes\n")

    def test_commentbug(self):
        ''' A "#" sign within an string is not a comment '''
        self.assertRenders("%if '#':\nyes\n%end\n", "yes\n")

    def test_multiline(self):
        ''' Block statements with non-terminating newlines '''
        self.assertRenders("%if 1\\\n%and 1:\nyes\n%end\n", "yes\n")

    def test_newline_in_parameterlist(self):
        ''' Block statements with non-terminating newlines in list '''
        self.assertRenders("%a=[1,\n%2]\n{{len(a)}}", "2")

    def test_dedentbug(self):
        ''' One-Line dednet blocks should not change indention '''
        t = '%if x: a="if"\n%else: a="else"\n%end\n{{a}}'
        self.assertRenders(t, "if", x=True)
        self.assertRenders(t, "else", x=False)
        t = '%if x:\n%a="if"\n%else: a="else"\n%end\n{{a}}'
        self.assertRenders(t, "if", x=True)
        self.assertRenders(t, "else", x=False)
        t = SimpleTemplate('%if x: a="if"\n%else: a="else"\n%end')
        self.assertRaises(NameError, t.render)

    def test_onelinebugs(self):
        ''' One-Line blocks should not change indention '''
        t = '%if x:\n%a=1\n%end\n{{a}}'
        self.assertRenders(t, "1", x=True)
        t = '%if x: a=1; end\n{{a}}'
        self.assertRenders(t, "1", x=True)
        t = '%if x:\n%a=1\n%else:\n%a=2\n%end\n{{a}}'
        self.assertRenders(t, "1", x=True)
        self.assertRenders(t, "2", x=False)
        t = '%if x:   a=1\n%else:\n%a=2\n%end\n{{a}}'
        self.assertRenders(t, "1", x=True)
        self.assertRenders(t, "2", x=False)
        t = '%if x:\n%a=1\n%else:   a=2; end\n{{a}}'
        self.assertRenders(t, "1", x=True)
        self.assertRenders(t, "2", x=False)
        t = '%if x:   a=1\n%else:   a=2; end\n{{a}}'
        self.assertRenders(t, "1", x=True)
        self.assertRenders(t, "2", x=False)

    def test_onelineblocks(self):
        """ Templates: one line code blocks """
        t = "start\n%a=''\n%for i in l: a += str(i); end\n{{a}}\nend"
        self.assertRenders(t, 'start\n123\nend', l=[1,2,3])
        self.assertRenders(t, 'start\n\nend', l=[])

    def test_escaped_codelines(self):
        self.assertRenders('\\% test', '% test')
        self.assertRenders('\\%% test', '%% test')
        self.assertRenders('    \\% test', '    % test')

    def test_nobreak(self):
        """ Templates: Nobreak statements"""
        self.assertRenders("start\\\\\n%pass\nend", 'startend')

    def test_nonobreak(self):
        """ Templates: Escaped nobreak statements"""
        self.assertRenders("start\\\\\n\\\\\n%pass\nend", 'start\\\\\nend')

    def test_include(self):
        """ Templates: Include statements"""
        with chdir(__file__):
            t = SimpleTemplate(name='stpl_include', lookup=['./views/'])
            self.assertRenders(t, 'before\nstart var end\nafter\n', var='var')

    def test_rebase(self):
        """ Templates: %rebase and method passing """
        with chdir(__file__):
            t = SimpleTemplate(name='stpl_t2main', lookup=['./views/'])
            result='+base+\n+main+\n!1234!\n+include+\n-main-\n+include+\n-base-\n'
            self.assertRenders(t, result, content='1234')

    def test_named_slots(self):
        source = "%with capture_slot('head'):\n" \
                 "<title>{{title}}</title>\n" \
                 "%end\n" \
                 "%with append_slot('head'):\n" \
                 '<meta name="value" content="{{value}}">\n' \
                 "%end\n" \
                 "%with append_slot('head'):\n" \
                 '<meta name="more">\n' \
                 "%end\n" \
                 "%with replace_slot('aside'):\n" \
                 "<aside>{{value}}</aside>\n" \
                 "%end\n" \
                 "HEAD:{{slot('head')}}\n" \
                 "ASIDE:{{slot('aside')}}\n" \
                 "DEFAULT:{{slot('missing', value)}}\n"
        result = "HEAD:<title>Home</title>\n" \
                 '<meta name="value" content="&lt;b&gt;">\n' \
                 '<meta name="more">\n' \
                 "ASIDE:<aside>&lt;b&gt;</aside>\n" \
                 "DEFAULT:&lt;b&gt;\n"
        self.assertRenders(source, result, title='Home', value='<b>')

    def test_rendered_slots_are_not_double_escaped(self):
        layout = SimpleTemplate("{{slot('content')}}|{{base}}")
        page = SimpleTemplate(dedent("""\
            %with replace('content'):
            <b>{{value}}</b>
            %end
            <i>{{value}}</i>
            %rebase('layout')
        """))
        page.cache.update(layout=layout)
        self.assertRenders(
            page,
            '<b>&lt;b&gt;</b>|&lt;i&gt;&amp;lt;b&amp;gt;&lt;/i&gt;\n',
            value='<b>')

    def test_named_slots_in_rebase_and_nested_includes(self):
        outer = SimpleTemplate(dedent("""
            HEAD:{{slot('head')}}
            ASIDE:{{slot('aside')}}
            {{!base}}
            SCRIPTS:{{slot('scripts')}}"""))
        middle = SimpleTemplate(dedent("""
            %with capture('head'):
            <meta name="middle">
            %end
            %with capture('aside'):
            <aside>middle default</aside>
            %end
            %with append('scripts'):
            <script>middle</script>
            %end
            MIDDLE-START
            {{!base}}
            MIDDLE-END
            %rebase('outer')
        """))
        child_a = SimpleTemplate(dedent("""
            CHILD-A
            %with append('scripts'):
            <script>a</script>
            %end
            %child_a_local = 'private-a'
            %_ = include('child_b')
            {{'defined' if defined('child_b_local') else 'isolated'}}
        """))
        child_b = SimpleTemplate(dedent("""
            CHILD-B {{value}}
            %with append('aside'):
            <aside>b {{value}}</aside>
            %end
            %with append('scripts'):
            <script>b {{value}}</script>
            %end
            %child_b_local = 'private-b'
        """))
        child_a.cache.update(child_b=child_b)
        middle.cache.update(outer=outer)
        page = SimpleTemplate(dedent("""
            %with replace('head'):
            <title>{{title}}</title>
            %end
            %with append('scripts'):
            <script>page</script>
            %end
            %_ = include('child_a')
            PAGE {{'defined' if defined('child_a_local') else 'isolated'}}
            %page_local = 'private-page'
            %rebase('middle')
        """))
        page.cache.update(middle=middle, child_a=child_a)

        result = '\n'.join((
            '',
            'HEAD:<title>Home &amp; away</title>',
            'ASIDE:<aside>b &lt;b&gt;</aside>',
            '',
            'MIDDLE-START',
            '',
            '',
            'CHILD-A',
            '',
            'CHILD-B &lt;b&gt;',
            'isolated',
            'PAGE isolated',
            '',
            'MIDDLE-END',
            '',
            'SCRIPTS:<script>page</script>',
            '<script>a</script>',
            '<script>b &lt;b&gt;</script>',
            '<script>middle</script>',
        ))
        self.assertRenders(page, result, title='Home & away', value='<b>')

    def test_named_slots_are_render_scoped_and_repeatable(self):
        child = SimpleTemplate(dedent("""\
            %with append('slot'):
            {{value}}
            %end
            %child_local = True
        """))
        page = SimpleTemplate(dedent("""\
            %_ = include('child')
            {{slot('slot')}}|{{'yes' if defined('child_local') else 'no'}}|{{slot('missing')}}"""))
        page.cache.update(child=child)
        self.assertRenders(page, 'first|no|', value='first')
        self.assertRenders(page, 'second|no|', value='second')

    def test_recursive_include_terminates_and_shares_slots(self):
        recursive = SimpleTemplate(dedent("""\
            {{depth}}
            %with append('path'):
            {{depth}}
            %end
            %if depth:
            %_ = include('recursive', depth=depth - 1)
            %end
        """))
        recursive.cache.update(recursive=recursive)
        page = SimpleTemplate(dedent("""\
            %_ = include('recursive', depth=2)
            |{{slot('path')}}"""))
        page.cache.update(recursive=recursive)
        self.assertRenders(page, '2\n1\n0\n|2\n1\n0')

    def test_get(self):
        self.assertRenders('{{get("x", "default")}}', '1234', x='1234')
        self.assertRenders('{{get("x", "default")}}', 'default')

    def test_setdefault(self):
        t = '%setdefault("x", "default")\n{{x}}'
        self.assertRenders(t, '1234', x='1234')
        self.assertRenders(t, 'default')

    def test_defnied(self):
        self.assertRenders('{{x if defined("x") else "no"}}', 'yes', x='yes')
        self.assertRenders('{{x if defined("x") else "no"}}', 'no')

    def test_notfound(self):
        """ Templates: Unavailable templates"""
        self.assertRaises(TemplateError, SimpleTemplate, name="abcdef", lookup=['.'])

    def test_error(self):
        """ Templates: Exceptions"""
        self.assertRaises(SyntaxError, lambda: SimpleTemplate('%for badsyntax').co)
        self.assertRaises(IndexError, SimpleTemplate('{{i[5]}}', lookup=['.']).render, i=[0])

    def test_winbreaks(self):
        """ Templates: Test windows line breaks """
        self.assertRenders('%var+=1\r\n{{var}}\r\n', '6\r\n', var=5)

    def test_winbreaks_end_bug(self):
        d = { 'test': [ 1, 2, 3 ] }
        self.assertRenders('%for i in test:\n{{i}}\n%end\n', '1\n2\n3\n', **d)
        self.assertRenders('%for i in test:\n{{i}}\r\n%end\n', '1\r\n2\r\n3\r\n', **d)
        self.assertRenders('%for i in test:\r\n{{i}}\n%end\r\n', '1\n2\n3\n', **d)
        self.assertRenders('%for i in test:\r\n{{i}}\r\n%end\r\n', '1\r\n2\r\n3\r\n', **d)

    def test_commentonly(self):
        """ Templates: Commentd should behave like code-lines (e.g. flush text-lines) """
        t = SimpleTemplate('...\n%#test\n...')
        self.assertNotEqual('#test', t.code.splitlines()[0])

    def test_template_shortcut(self):
        result = template('start {{var}} end', var='middle')
        self.assertEqual(touni('start middle end'), result)

    def test_view_decorator(self):
        @view('start {{var}} end')
        def test():
            return dict(var='middle')
        self.assertEqual(touni('start middle end'), test())

    def test_view_decorator_issue_407(self):
        with chdir(__file__):
            @view('stpl_no_vars')
            def test():
                pass
            self.assertEqual(touni('hihi'), test())
            @view('aaa {{x}}', x='bbb')
            def test2():
                pass
            self.assertEqual(touni('aaa bbb'), test2())

    def test_global_config(self):
        SimpleTemplate.global_config('meh', 1)
        t = SimpleTemplate('anything')
        self.assertEqual(touni('anything'), t.render())

    def test_bug_no_whitespace_before_stmt(self):
        self.assertRenders('\n{{var}}', '\nx', var='x')

    def test_bug_block_keywords_eat_prefixed_code(self):
        ''' #595: Everything before an 'if' statement is removed, resulting in
            SyntaxError. '''
        tpl = "% m = 'x' if True else 'y'\n{{m}}"
        self.assertRenders(tpl, 'x')


class TestSTPLDir(unittest.TestCase):
    def fix_ident(self, string):
        lines = string.splitlines(True)
        if not lines: return string
        if not lines[0].strip(): lines.pop(0)
        whitespace = re.match('([ \t]*)', lines[0]).group(0)
        if not whitespace: return string
        for i in range(len(lines)):
            lines[i] = lines[i][len(whitespace):]
        return lines[0][:0].join(lines)

    def assertRenders(self, source, result, syntax=None, *args, **vars):
        source = self.fix_ident(source)
        result = self.fix_ident(result)
        tpl = SimpleTemplate(source, syntax=syntax)
        try:
            tpl.co
            self.assertEqual(touni(result), tpl.render(*args, **vars))
        except SyntaxError:
            self.fail('Syntax error in template:\n%s\n\nTemplate code:\n##########\n%s\n##########' %
                     (traceback.format_exc(), tpl.code))

    def test_multiline_block(self):
        source = '''
            <% a = 5
            b = 6
            c = 7 %>
            {{a+b+c}}
        '''; result = '''
            18
        '''
        self.assertRenders(source, result)
        source_wineol = '<% a = 5\r\nb = 6\r\nc = 7\r\n%>\r\n{{a+b+c}}'
        result_wineol = '18'
        self.assertRenders(source_wineol, result_wineol)

    def test_multiline_ignore_eob_in_string(self):
        source = '''
            <% x=5 # a comment
               y = '%>' # a string
               # this is still code
               # lets end this %>
            {{x}}{{!y}}
        '''; result = '''
            5%>
        '''
        self.assertRenders(source, result)

    def test_multiline_find_eob_in_comments(self):
        source = '''
            <% # a comment
               # %> ignore because not end of line
               # this is still code
               x=5
               # lets end this here %>
            {{x}}
        '''; result = '''
            5
        '''
        self.assertRenders(source, result)

    def test_multiline_indention(self):
        source = '''
            <%   if True:
                   a = 2
                     else:
                       a = 0
                         end
            %>
            {{a}}
        '''; result = '''
            2
        '''
        self.assertRenders(source, result)

    def test_multiline_eob_after_end(self):
        source = '''
            <%   if True:
                   a = 2
                 end %>
            {{a}}
        '''; result = '''
            2
        '''
        self.assertRenders(source, result)

    def test_multiline_eob_in_single_line_code(self):
        # eob must be a valid python expression to allow this test.
        source = '''
            cline eob=5; eob
            xxx
        '''; result = '''
            xxx
        '''
        self.assertRenders(source, result, syntax='sob eob cline foo bar')

    def test_multiline_strings_in_code_line(self):
        source = '''
            % a = """line 1
                  line 2"""
            {{a}}
        '''; result = '''
            line 1
                  line 2
        '''
        self.assertRenders(source, result)

    def test_multiline_comprehensions_in_code_line(self):
        self.assertRenders(source='''
            % a = [
            %    (i + 1)
            %    for i in range(5)
            %    if i%2 == 0
            % ]
            {{a}}
        ''', result='''
            [1, 3, 5]
        ''')


    def test_end_keyword_on_same_line(self):
        self.assertRenders('''
            % if 1:
            %    1; end
            foo
        ''', '''
            foo
        ''')
