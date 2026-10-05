# Streaming Responses

Sometimes you might need to receive a streaming response.
You can do this with the `on_data` request option.

The `on_data` callback is a receives tuples of chunk Strings, and the total
of received bytes so far.

This example implements such a callback:

```ruby
# A buffer to store the streamed data
streamed = []

conn = Faraday.new('http://httpbingo.org')
conn.get('/stream/100') do |req|
  # Set a callback which will receive tuples of chunk Strings,
  # the sum of characters received so far, and the response environment.
  # The latter will allow access to the response status, headers and reason, as well as the request info.
  req.options.on_data = Proc.new do |chunk, overall_received_bytes, env|
    puts "Received #{overall_received_bytes} characters"
    streamed << chunk
  end
end

# Joins all response chunks together
streamed.join
```

The `on_data` streaming is currently only supported by some adapters.
To see which ones, please refer to [Awesome Faraday][awesome] comparative table or check the adapter documentation.
Moreover, the `env` parameter was only recently added, which means some adapters may only have partial support
(i.e. only `chunk` and `overall_received_bytes` will be passed to your block).

## Amazon EventStream

For Amazon EventStream responses, use `Faraday::EventStream::Decoder` as the
`on_data` handler. It buffers chunks split at arbitrary byte boundaries and
only yields a message after validating the prelude CRC, frame lengths, typed
headers, and message CRC. Faraday calls `finish` automatically when the
response completes, so a truncated final frame raises an error.

```ruby
decoder = Faraday::EventStream::Decoder.new do |message, env|
  message.headers.each do |name, header|
    puts "#{name}: #{header.value} (#{header.type})"
  end
  process(message.payload)
end

connection.get('/events') do |request|
  request.options.on_data = decoder
end
```

Protocol errors subclass `Faraday::EventStream::Error` and expose
`message_number` (1-based) and `byte_position` (0-based). Error messages do
not include payload data. Unrecognized header type bytes in the reserved
legal range raise `UnknownHeaderTypeError`; invalid type bytes raise
`InvalidHeaderTypeError`.

[awesome]:      https://github.com/lostisland/awesome-faraday/#adapters
