# Getting Started

This guide explains how to use `protocol-websocket` for implementing a websocket client and server.

## Installation

Add the gem to your project:

~~~ bash
$ bundle add protocol-websocket
~~~

## Core Concepts

`protocol-websocket` has several core concepts:

- A {ruby Protocol::WebSocket::Frame} is the base class which is used to represent protocol-specific structured frames.
- A {ruby Protocol::WebSocket::Framer} wraps an underlying {ruby Async::IO::Stream} for reading and writing binary data into structured frames.
- A {ruby Protocol::WebSocket::Connection} wraps a framer and implements for implementing connection specific interactions like reading and writing text.
- A {ruby Protocol::WebSocket::Message} is a higher-level abstraction for reading and writing messages.

## Bi-directional Communication

We can create a small bi-directional WebSocket client server:

~~~ ruby
require 'protocol/websocket'
require 'protocol/websocket/connection'
require 'socket'

sockets = Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)

client = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.first))
server = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.last))

client.send_text("Hello World")
server.read
# #<Protocol::WebSocket::TextMessage:0x000000011d2338e0 @buffer="Hello World">

client.send_binary("Hello World")
server.read
#<Protocol::WebSocket::BinaryMessage:0x000000011d371db0 @buffer="Hello World">
~~~

## Client And Server Roles

RFC 6455 requires frames sent by a *client* to be masked and frames sent by a *server* to be unmasked. Pass the `role:` keyword to {ruby Protocol::WebSocket::Connection} to enable strict enforcement in both directions:

~~~ ruby
client = Protocol::WebSocket::Connection.new(framer, role: :client)
server = Protocol::WebSocket::Connection.new(framer, role: :server)
~~~

- `role: :client` generates a random 4-byte outgoing mask (you can also pass an explicit `mask:`) and requires every *incoming* frame to be unmasked.
- `role: :server` sends unmasked frames and requires every *incoming* frame to be masked.
- When a violating frame is received, a {ruby Protocol::WebSocket::ProtocolError} is raised *before* the payload is read, and the connection is closed with the error's `code` (e.g. `1002` for a protocol error or `1009` for an oversized frame). You can inspect that code via `ProtocolError#code`.

The role is never inferred from whether an outgoing mask happens to be configured; it must be stated explicitly.

### Compatibility Mode

Omitting `role:` (the default, `role: nil`) preserves the legacy behaviour used by older callers: no masking is enforced on either read or write, even though all structural frame validation (FIN, RSV, reserved opcodes, control frame length and length encoding) still applies. This mode is kept for backwards compatibility and for custom transports; new connections should pass `role: :client` or `role: :server`.

## Messages

We can also use the {ruby Protocol::WebSocket::Message} class to read and write messages:

~~~ ruby
require 'protocol/websocket'
require 'protocol/websocket/connection'
require 'socket'

sockets = Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)

client = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.first))
server = Protocol::WebSocket::Connection.new(Protocol::WebSocket::Framer.new(sockets.last))

# Encode a value using JSON:
message = Protocol::WebSocket::TextMessage.generate({hello: "world"})

client.write(message)
server.read.to_h
# {:hello=>"world"}
~~~

### Text Messages

Text messages contain UTF-8 encoded text. Invalid UTF-8 sequences will result in errors. Text messages are useful for sending structured data like JSON.

### Binary Messages

Binary messages contain arbitrary binary data. They can be used to send any kind of data. Binary messages are useful for sending files or other binary data, like images or video.
