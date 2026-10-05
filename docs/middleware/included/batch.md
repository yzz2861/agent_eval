# Batch Requests (multipart/mixed)

The `Batch` request middleware packs several independent sub-requests into a
single outer `multipart/mixed` HTTP request. Each part encapsulates one
sub-request as `application/http`, preserving its method, relative target,
headers, body and a unique `Content-ID`.

Sub-responses are correlated back to their request by `Content-ID`, so the
server is free to return them out of order. The decoded response body is a
`Faraday::Batch::Response` whose results are always presented in the same
order as the requests:

* each result keeps its own inner HTTP status, headers and body;
* an outer HTTP 200 is never treated as success for every item;
* requested IDs missing from the response are represented explicitly with a
  `Faraday::Batch::MissingResponseError` on the result;
* duplicate IDs are rejected when building the request;
* the batch is sent once and is never retried automatically.

The generated multipart boundary is guaranteed not to occur in any sub-request
body, including binary bodies.

### Example Usage

```ruby
conn = Faraday.new(url: 'https://api.example.com') do |f|
  f.request :batch
  f.adapter Faraday.default_adapter
end

batch = Faraday::Batch::Request.new
batch.request(:get, '/articles/1', nil, {}, id: 'one')
batch.request(:post, '/articles', '{"title":"Hello"}',
              { 'Content-Type' => 'application/json' }, id: 'two')

response = conn.post('/batch', batch)
results = response.body

results.map(&:id)         # => ['one', 'two'] regardless of wire order
results['one'].status     # => 200
results['two'].status     # => 422, kept even when the outer status is 200
results['two'].error?     # => true
results.missing           # => results for IDs absent from the response
results.success?          # => true only when every item returned 2xx
results.unexpected        # => parts returned with unknown/duplicate IDs
```

### Encoding and decoding without the middleware

`Faraday::Batch::Encoder` and `Faraday::Batch::Decoder` can also be used
directly:

```ruby
encoder = Faraday::Batch::Encoder.new(batch)
encoder.headers # => { 'Content-Type' => 'multipart/mixed; boundary=...' }
encoder.body    # => binary-safe multipart request body

decoded = Faraday::Batch::Decoder.decode(batch.ids, outer_status,
                                         outer_headers, outer_body)
```
