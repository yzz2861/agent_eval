# gRPC-Web

The `grpc_web` request middleware provides lightweight unary gRPC-Web support.
It does not generate protobuf classes or depend on a full gRPC runtime. Your
application supplies an already-encoded protobuf message as a binary `String`,
and the response body is the unframed protobuf message.

## Binary transport

Binary mode is the default and uses `application/grpc-web+proto`.

```ruby
conn = Faraday.new do |f|
  f.request :grpc_web
  f.adapter :net_http
end

response = conn.post('/example.ExampleService/Unary', encoded_protobuf)
response.body # => encoded response protobuf as binary String
response.headers['grpc-status'] # => "0"
```

## Base64 text transport

Text mode uses `application/grpc-web-text+proto`. Both request and response
bodies are base64-encoded. The response decoder accepts chunks split anywhere,
including inside a base64 four-character group.

```ruby
conn = Faraday.new do |f|
  f.request :grpc_web, mode: :text
  f.adapter :net_http
end
```

## Frame limits

The default maximum frame payload size is 4 MiB. Configure `max_frame_size` to
reject larger request or response frames without buffering an oversized payload.

```ruby
conn = Faraday.new do |f|
  f.request :grpc_web, max_frame_size: 1024
  f.adapter :net_http
end
```

## Status handling

HTTP status and gRPC status are checked separately:

- An HTTP status other than 200 raises `Faraday::GRPCWeb::HTTPError`.
- HTTP 200 with non-zero `grpc-status` raises `Faraday::GRPCWeb::StatusError`.
- Malformed frames, truncated responses, compressed frames, and more than one
  unary data frame raise `Faraday::GRPCWeb::ProtocolError`.

Successful unary responses require exactly one data frame followed by a
trailer frame. Trailers-only error responses are also supported.
