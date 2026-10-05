# Batch Requests (multipart/mixed)

The `Batch` request middleware sends several sub-requests in a single HTTP
request encoded as `multipart/mixed`, and decodes the sub-responses back into a
`Faraday::Batch::BatchResult`.

Each sub-request is a `Faraday::Batch::Part` and keeps its HTTP method,
relative target, headers, body and a unique `Content-ID`:

```ruby
parts = [
  Faraday::Batch::Part.new(method: :get,  path: '/users/1', content_id: '1'),
  Faraday::Batch::Part.new(method: :post, path: '/users',
                           headers: { 'Content-Type' => 'application/json' },
                           body: { name: 'Ada' }.to_json,
                           content_id: '2')
]
```

## Sending a batch

```ruby
conn = Faraday.new('https://api.example.com') do |f|
  f.request :batch
  f.adapter Faraday.default_adapter
end

batch = conn.post('/batch', parts).body
# => #<Faraday::Batch::BatchResult>
```

The middleware sets the outer `Content-Type` to `multipart/mixed` with a
collision-free boundary and wraps each part as an `application/http` message.
Sub-bodies are binary-safe: a boundary that appears inside a sub-body is
detected and replaced automatically, while an explicitly provided colliding
boundary raises a `Faraday::Batch::BoundaryCollisionError`.

## Reading the results

Sub-responses may arrive out of order. They are matched back to the requests by
`Content-ID`, so results are always returned in request order and can also be
looked up by ID:

```ruby
batch.content_ids            # => ['1', '2']
batch['1'].status            # => 200
batch['2'].error             # => Faraday::ResourceNotFound for a 404
batch.results                # => [PartResult, PartResult]
batch.failed                 # => parts with a 4xx/5xx status
batch.missing                # => requested IDs absent from the response
batch.all_succeeded?         # => true only if every part returned 2xx
```

Each `Faraday::Batch::PartResult` exposes `content_id`, `status`, `headers`,
`body` and `error`. The outer response status is available as
`batch.outer_status`, but an outer `200` is never treated as success for the
individual parts.

## Failures and missing parts

* Duplicate `Content-ID`s raise `Faraday::Batch::DuplicateContentIdError`
  before anything is sent.
* A requested ID missing from the response is still present in `results`, with
  `status == nil` and a `Faraday::Batch::MissingPartError` as `error`.
* When the outer response is not `multipart/mixed` (for example an outer 500
  error page), every requested ID becomes such a missing result and the outer
  response is kept on `outer_status`/`outer_headers`/`outer_body`.
* The middleware performs exactly one request and never retries the batch.
