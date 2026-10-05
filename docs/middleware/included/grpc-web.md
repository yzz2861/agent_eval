# gRPC-Web (unary)

The `grpc_web` request and response middleware provide lightweight unary
[gRPC-Web](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md)
support. Callers provide already-encoded protobuf bytes and receive raw
protobuf bytes back: Faraday does not generate protobuf classes and does
not depend on a gRPC runtime.

## gRPC-Web Requests

The request middleware frames the body (a `String` of encoded protobuf
bytes) into a single gRPC-Web data frame and sets the `Content-Type`,
`Accept`, `X-Grpc-Web`, and `TE` headers.

The behaviour can be customized with the following options:
* **mode:** `:binary` (default) sends `application/grpc-web` with raw
  frames; `:text` sends `application/grpc-web-text` with the frames
  base64-encoded.

### Example Usage

```ruby
conn = Faraday.new(...) do |f|
  f.request :grpc_web, mode: :binary
  f.response :grpc_web
  ...
end

response = conn.post('/pkg.Service/Method', MyMessage.encode(message))
# POST with
# Content-Type: application/grpc-web
# X-Grpc-Web: 1
# TE: trailers
# Body: 0x00 + 4-byte length + protobuf bytes
```

## gRPC-Web Responses

The response middleware parses the data and trailers frames of the
response, in both binary and base64 text form, and replaces the body with
the raw protobuf message bytes. The HTTP status and the `grpc-status`
trailer are checked independently:

* a non-2xx HTTP status raises `Faraday::ClientError`/`Faraday::ServerError`,
* a non-zero `grpc-status` trailer raises `Faraday::GrpcWeb::StatusError`,
  which carries `grpc_status` and `grpc_message` readers,
* malformed, truncated, oversized, or extra frames raise
  `Faraday::GrpcWeb::ProtocolError`.

The parsed `Faraday::GrpcWeb::Result` (message bytes plus trailers) is
available as `response.env[:grpc_web]`.

The behaviour can be customized with the following options:
* **max_frame_size:** maximum accepted size of a single frame payload,
  in bytes. Defaults to 4 MiB.

```ruby
response = conn.post('/pkg.Service/Method', payload)
response.body                    # => raw protobuf bytes
response.env[:grpc_web].trailers # => { 'grpc-status' => '0', ... }
```
