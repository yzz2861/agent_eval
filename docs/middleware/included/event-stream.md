# Event Stream Decoding

The `EventStream` response middleware decodes an Amazon EventStream
(`application/vnd.amazon.eventstream`) response and yields every validated
`Faraday::EventStream::Message` to your block.

Each message is framed as a prelude (total length, headers length and a
prelude CRC32), a block of typed headers, the payload and a trailing message
CRC32. The prelude CRC is verified before its length fields are trusted, and
a message is only yielded after its message CRC has been verified too.
Response chunks may be split at any byte boundary; if the stream ends in the
middle of a message, a `Faraday::EventStream::TruncationError` is raised.

### Example Usage

```ruby
conn = Faraday.new(...) do |f|
  f.response :event_stream do |message|
    puts message.headers.inspect # typed headers, e.g. { ":message-type" => "event" }
    puts message.payload         # raw payload bytes
  end
  ...
end

conn.get('/stream')
```

When the adapter streams the response, chunks are decoded incrementally;
otherwise the buffered body is decoded when the response completes.

### Errors

All decoding errors inherit from `Faraday::EventStream::Error` and carry the
sequence number of the message being decoded (`message_index`) and the
absolute byte offset in the stream (`byte_offset`). Payload bytes are never
included in error messages.

* `Faraday::EventStream::PreludeCrcError` - the prelude CRC did not match.
* `Faraday::EventStream::MessageCrcError` - the message CRC did not match.
* `Faraday::EventStream::TruncationError` - the stream ended mid-message.
* `Faraday::EventStream::ProtocolError` - the frame violates the protocol.
* `Faraday::EventStream::InvalidHeaderTypeError` - a header value type byte
  outside the protocol-defined 0-9 range.

Headers whose names are not known to Faraday are legal and preserved as-is.

### Standalone decoding

The decoder can also be used directly, without the middleware:

```ruby
decoder = Faraday::EventStream::Decoder.new
decoder.feed(chunk) { |message| handle(message) }
decoder.finish # raises Faraday::EventStream::TruncationError on a partial message
```
