# Multistatus (WebDAV) parsing

The `Multistatus` response middleware parses WebDAV `207 Multi-Status` bodies
(RFC 4918) into a structured result. It only activates when the response
content type matches XML (`application/xml`, `text/xml` or any `+xml` type)
and the document root is a `DAV:` `multistatus` element; anything else is
left untouched.

\`\`\`ruby
conn = Faraday.new(url: 'https://dav.example.com') do |f|
  f.response :multistatus
  # or with options:
  # f.response :multistatus, content_type: /\bxml$/, preserve_raw: true
end

result = conn.request(:propfind, '/dir/').body
# => #<Faraday::Response::Multistatus::Result>
\`\`\`

## Reading the result

Resources are keyed by **absolute href**: relative hrefs are resolved against
the request URI. If a server returns the same href in more than one
`<response>` element, they are merged into a single resource — propstats are
appended in document order and the resource-level status/description are kept
from the first `<response>` that defines them.

\`\`\`ruby
resource = result['https://dav.example.com/dir/file.txt']
resource.status            # => "HTTP/1.1 200 OK" (resource-level, may be nil)
resource.status_code       # => 200
resource.propstats         # => [#<PropStat>, ...]
\`\`\`

Each `propstat` keeps its own status and error description, and its
properties are keyed by **expanded name** (`{namespace}local-name`), so
properties with the same local name from different namespaces never collide:

\`\`\`ruby
propstat = resource.propstats.first
propstat.status_code          # => 200
propstat.response_description # => nil
propstat['{DAV:}getcontentlength'].value            # => "1234"
propstat['{http://example.com/ns}displayname'].value # => "zed"
\`\`\`

## XML safety

Parsing uses REXML, a pure-Ruby parser that performs no network access.
Documents containing a `<!DOCTYPE` declaration are rejected with a
`Faraday::ParsingError`, which disables all internal and external entity
definitions (XXE).
