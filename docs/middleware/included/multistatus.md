# WebDAV Multi-Status Responses

The `Multistatus` response middleware parses WebDAV `207 Multi-Status` bodies
(RFC 4918). A multi-status body carries one `<response>` element per resource,
and each resource groups its properties into `<propstat>` blocks that have
their own status line, so different properties of the same resource can have
different outcomes.

The middleware replaces the response body with a
`Faraday::Response::Multistatus::Result`:

* Resources are keyed by **absolute href**; relative hrefs are resolved
  against the request URI.
* Properties are keyed by **expanded name** (`{namespace-uri}local`, Clark
  notation), so properties sharing a local name in different namespaces are
  never merged. Property values are their text content (`nil` when empty).
* Every `<propstat>` keeps its own status line, numeric status code, `<error>`
  and `<responsedescription>`.
* When the same href appears in several `<response>` elements, they are
  **merged into a single resource**: propstats are appended in document order
  and non-nil error/description values from later elements take precedence.

### Example Usage

```ruby
conn = Faraday.new(...) do |f|
  f.response :multistatus
end

response = conn.propfind('/container/')
result = response.body
# => #<Faraday::Response::Multistatus::Result>

result['https://example.com/container/file.txt'].properties
# => { "{DAV:}displayname" => "file.txt", "{DAV:}getcontentlength" => "42" }

result['https://example.com/container/file.txt'].propstats
# => [#<Propstat status="HTTP/1.1 200 OK" ...>, #<Propstat status="HTTP/1.1 404 Not Found" ...>]

result['https://example.com/container/file.txt'].propstats.last.status_code
# => 404
```

### Configuration

The middleware only parses responses with a matching status (default: `207`)
and an XML content type (default: `/\bxml$/`). Both can be customized, and the
raw body can be preserved:

```ruby
Faraday.new(...) do |f|
  f.response :multistatus, statuses: [207, 200],
                           content_type: 'application/xml',
                           preserve_raw: true
end
```

### Security

Bodies containing a `<!DOCTYPE` declaration are rejected with a
`Faraday::ParsingError`, which disables DTDs, (external) entity expansion and
any form of network loading. The parser (REXML) never performs network access
itself.

