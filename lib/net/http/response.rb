# frozen_string_literal: true

# This class is the base class for \Net::HTTP response classes.
#
# == About the Examples
#
# :include: doc/net-http/examples.rdoc
#
# == Returned Responses
#
# \Method Net::HTTP.get_response returns
# an instance of one of the subclasses of \Net::HTTPResponse:
#
#   Net::HTTP.get_response(uri)
#   # => #<Net::HTTPOK 200 OK readbody=true>
#   Net::HTTP.get_response(hostname, '/nosuch')
#   # => #<Net::HTTPNotFound 404 Not Found readbody=true>
#
# As does method Net::HTTP#request:
#
#   req = Net::HTTP::Get.new(uri)
#   Net::HTTP.start(hostname) do |http|
#     http.request(req)
#   end # => #<Net::HTTPOK 200 OK readbody=true>
#
# \Class \Net::HTTPResponse includes module Net::HTTPHeader,
# which provides access to response header values via (among others):
#
# - \Hash-like method <tt>[]</tt>.
# - Specific reader methods, such as +content_type+.
#
# Examples:
#
#   res = Net::HTTP.get_response(uri) # => #<Net::HTTPOK 200 OK readbody=true>
#   res['Content-Type']               # => "text/html; charset=UTF-8"
#   res.content_type                  # => "text/html"
#
# == Response Subclasses
#
# \Class \Net::HTTPResponse has a subclass for each
# {HTTP status code}[https://en.wikipedia.org/wiki/List_of_HTTP_status_codes].
# You can look up the response class for a given code:
#
#   Net::HTTPResponse::CODE_TO_OBJ['200'] # => Net::HTTPOK
#   Net::HTTPResponse::CODE_TO_OBJ['400'] # => Net::HTTPBadRequest
#   Net::HTTPResponse::CODE_TO_OBJ['404'] # => Net::HTTPNotFound
#
# And you can retrieve the status code for a response object:
#
#   Net::HTTP.get_response(uri).code                 # => "200"
#   Net::HTTP.get_response(hostname, '/nosuch').code # => "404"
#
# The response subclasses (indentation shows class hierarchy):
#
# - Net::HTTPUnknownResponse (for unhandled \HTTP extensions).
#
# - Net::HTTPInformation:
#
#   - Net::HTTPContinue (100)
#   - Net::HTTPSwitchProtocol (101)
#   - Net::HTTPProcessing (102)
#   - Net::HTTPEarlyHints (103)
#
# - Net::HTTPSuccess:
#
#   - Net::HTTPOK (200)
#   - Net::HTTPCreated (201)
#   - Net::HTTPAccepted (202)
#   - Net::HTTPNonAuthoritativeInformation (203)
#   - Net::HTTPNoContent (204)
#   - Net::HTTPResetContent (205)
#   - Net::HTTPPartialContent (206)
#   - Net::HTTPMultiStatus (207)
#   - Net::HTTPAlreadyReported (208)
#   - Net::HTTPIMUsed (226)
#
# - Net::HTTPRedirection:
#
#   - Net::HTTPMultipleChoices (300)
#   - Net::HTTPMovedPermanently (301)
#   - Net::HTTPFound (302)
#   - Net::HTTPSeeOther (303)
#   - Net::HTTPNotModified (304)
#   - Net::HTTPUseProxy (305)
#   - Net::HTTPTemporaryRedirect (307)
#   - Net::HTTPPermanentRedirect (308)
#
# - Net::HTTPClientError:
#
#   - Net::HTTPBadRequest (400)
#   - Net::HTTPUnauthorized (401)
#   - Net::HTTPPaymentRequired (402)
#   - Net::HTTPForbidden (403)
#   - Net::HTTPNotFound (404)
#   - Net::HTTPMethodNotAllowed (405)
#   - Net::HTTPNotAcceptable (406)
#   - Net::HTTPProxyAuthenticationRequired (407)
#   - Net::HTTPRequestTimeOut (408)
#   - Net::HTTPConflict (409)
#   - Net::HTTPGone (410)
#   - Net::HTTPLengthRequired (411)
#   - Net::HTTPPreconditionFailed (412)
#   - Net::HTTPRequestEntityTooLarge (413)
#   - Net::HTTPRequestURITooLong (414)
#   - Net::HTTPUnsupportedMediaType (415)
#   - Net::HTTPRequestedRangeNotSatisfiable (416)
#   - Net::HTTPExpectationFailed (417)
#   - Net::HTTPMisdirectedRequest (421)
#   - Net::HTTPUnprocessableEntity (422)
#   - Net::HTTPLocked (423)
#   - Net::HTTPFailedDependency (424)
#   - Net::HTTPUpgradeRequired (426)
#   - Net::HTTPPreconditionRequired (428)
#   - Net::HTTPTooManyRequests (429)
#   - Net::HTTPRequestHeaderFieldsTooLarge (431)
#   - Net::HTTPUnavailableForLegalReasons (451)
#
# - Net::HTTPServerError:
#
#   - Net::HTTPInternalServerError (500)
#   - Net::HTTPNotImplemented (501)
#   - Net::HTTPBadGateway (502)
#   - Net::HTTPServiceUnavailable (503)
#   - Net::HTTPGatewayTimeOut (504)
#   - Net::HTTPVersionNotSupported (505)
#   - Net::HTTPVariantAlsoNegotiates (506)
#   - Net::HTTPInsufficientStorage (507)
#   - Net::HTTPLoopDetected (508)
#   - Net::HTTPNotExtended (510)
#   - Net::HTTPNetworkAuthenticationRequired (511)
#
# There is also the Net::HTTPBadResponse exception which is raised when
# there is a protocol error.
#
class Net::HTTPResponse
  # The maximum total size in bytes of the response header.
  MAX_RESPONSE_HEADER_LENGTH = 1024 * 1024 # 1 MiB

  # The maximum number of informational (1xx) responses accepted before the
  # final response.
  MAX_INFORMATIONAL_RESPONSES = 100

  class << self
    # true if the response has a body.
    def body_permitted?
      self::HAS_BODY
    end

    def exception_type   # :nodoc: internal use only
      self::EXCEPTION_TYPE
    end

    def read_new(sock)   #:nodoc: internal use only
      httpv, code, msg = read_status_line(sock)
      res = response_class(code).new(httpv, code, msg)
      each_response_header(sock) do |k,v|
        res.add_field k, v
      end
      res
    end

    def read_line(sock, limit, ignore_eof = false)   #:nodoc: internal use only
      sock.readuntil("\n", ignore_eof, limit: limit)
    rescue Net::ReadLimitExceeded
      raise Net::HTTPBadResponse, 'response line too long'
    end

    private
    # :stopdoc:

    def read_status_line(sock)
      str = read_line(sock, MAX_RESPONSE_HEADER_LENGTH).chop
      m = /\AHTTP(?:\/(\d+\.\d+))?\s+(\d\d\d)(?:\s+(.*))?\z/in.match(str) or
        raise Net::HTTPBadResponse, "wrong status line: #{str.dump}"
      m.captures
    end

    def response_class(code)
      CODE_TO_OBJ[code] or
      CODE_CLASS_TO_OBJ[code[0,1]] or
      Net::HTTPUnknownResponse
    end

    def each_response_header(sock)
      key = value = nil
      remaining = MAX_RESPONSE_HEADER_LENGTH
      while true
        line = read_line(sock, MAX_RESPONSE_HEADER_LENGTH, true)
        remaining -= line.bytesize
        raise Net::HTTPBadResponse, 'response header too large' if remaining < 0
        line = line.sub(/\s+\z/, '')
        break if line.empty?
        if line[0] == ?\s or line[0] == ?\t and value
          value << ' ' unless value.empty?
          value << line.strip
        else
          yield key, value if key
          key, value = line.strip.split(/\s*:\s*/, 2)
          raise Net::HTTPBadResponse, 'wrong header line format' if value.nil?
        end
      end
      yield key, value if key
    end
  end

  # next is to fix bug in RDoc, where the private inside class << self
  # spills out.
  public

  include Net::HTTPHeader

  def initialize(httpv, code, msg)   #:nodoc: internal use only
    @http_version = httpv
    @code         = code
    @message      = msg
    initialize_http_header nil
    @body = nil
    @read = false
    @uri  = nil
    @decode_content = false
    @body_encoding = false
    @ignore_eof = true
  end

  # The HTTP version supported by the server.
  attr_reader :http_version

  # The HTTP result code string. For example, '302'.  You can also
  # determine the response type by examining which response subclass
  # the response object is an instance of.
  attr_reader :code

  # The HTTP result message sent by the server. For example, 'Not Found'.
  attr_reader :message
  alias msg message   # :nodoc: obsolete

  # The URI used to fetch this response.  The response URI is only available
  # if a URI was used to create the request.
  attr_reader :uri

  # Set to true automatically when the request did not contain an
  # Accept-Encoding header from the user.
  attr_accessor :decode_content

  # Returns the value set by body_encoding=, or +false+ if none;
  # see #body_encoding=.
  attr_reader :body_encoding

  # Sets the encoding that should be used when reading the body:
  #
  # - If the given value is an Encoding object, that encoding will be used.
  # - Otherwise if the value is a string, the value of
  #   {Encoding#find(value)}[https://docs.ruby-lang.org/en/master/Encoding.html#method-c-find]
  #   will be used.
  # - Otherwise an encoding will be deduced from the body itself.
  #
  # Examples:
  #
  #   http = Net::HTTP.new(hostname)
  #   req = Net::HTTP::Get.new('/')
  #
  #   http.request(req) do |res|
  #     p res.body.encoding # => #<Encoding:ASCII-8BIT>
  #   end
  #
  #   http.request(req) do |res|
  #     res.body_encoding = "UTF-8"
  #     p res.body.encoding # => #<Encoding:UTF-8>
  #   end
  #
  def body_encoding=(value)
    value = Encoding.find(value) if value.is_a?(String)
    @body_encoding = value
  end

  # Whether to ignore EOF when reading bodies with a specified Content-Length
  # header.
  attr_accessor :ignore_eof

  def inspect   # :nodoc:
    "#<#{self.class} #{@code} #{@message} readbody=#{@read}>"
  end

  #
  # response <-> exception relationship
  #

  def code_type   #:nodoc:
    self.class
  end

  def error!   #:nodoc:
    message = @code
    message = "#{message} #{@message.dump}" if @message
    raise error_type().new(message, self)
  end

  def error_type   #:nodoc:
    self.class::EXCEPTION_TYPE
  end

  # Raises an HTTP error if the response is not 2xx (success).
  def value
    error! unless self.kind_of?(Net::HTTPSuccess)
  end

  def uri= uri # :nodoc:
    @uri = uri.dup if uri
  end

  #
  # header (for backward compatibility only; DO NOT USE)
  #

  def response   #:nodoc:
    warn "Net::HTTPResponse#response is obsolete", uplevel: 1 if $VERBOSE
    self
  end

  def header   #:nodoc:
    warn "Net::HTTPResponse#header is obsolete", uplevel: 1 if $VERBOSE
    self
  end

  def read_header   #:nodoc:
    warn "Net::HTTPResponse#read_header is obsolete", uplevel: 1 if $VERBOSE
    self
  end

  #
  # body
  #

  def reading_body(sock, reqmethodallowbody)  #:nodoc: internal use only
    @socket = sock
    @body_exist = reqmethodallowbody && self.class.body_permitted?
    begin
      yield
      self.body unless @body_stream&.open?   # ensure to read body
    ensure
      @socket = nil unless @body_stream&.open?
    end
  end

  # Gets the entity body returned by the remote HTTP server.
  #
  # If a block is given, the body is passed to the block, and
  # the body is provided in fragments, as it is read in from the socket.
  #
  # If +dest+ argument is given, response is read into that variable,
  # with <code>dest#<<</code> method (it could be String or IO, or any
  # other object responding to <code><<</code>).
  #
  # Calling this method a second or subsequent time for the same
  # HTTPResponse object will return the value already read.
  #
  #   http.request_get('/index.html') {|res|
  #     puts res.read_body
  #   }
  #
  #   http.request_get('/index.html') {|res|
  #     p res.read_body.object_id   # 538149362
  #     p res.read_body.object_id   # 538149362
  #   }
  #
  #   # using iterator
  #   http.request_get('/index.html') {|res|
  #     res.read_body do |segment|
  #       print segment
  #     end
  #   }
  #
  def read_body(dest = nil, &block)
    if @read
      raise IOError, "#{self.class}\#read_body called twice" if dest or block
      return @body
    end
    to = procdest(dest, block)
    stream_check
    if @body_exist
      read_body_0 to
      @body = to
    else
      @body = nil
    end
    @read = true
    return if @body.nil?

    case enc = @body_encoding
    when Encoding, false, nil
      # Encoding: force given encoding
      # false/nil: do not force encoding
    else
      # other value: detect encoding from body
      enc = detect_encoding(@body)
    end

    @body.force_encoding(enc) if enc

    @body
  end

  # Returns a Net::HTTPResponse::BodyStream for reading the response body
  # incrementally, instead of buffering it as a single string.
  #
  # The stream must be taken while the response is being delivered, that is,
  # inside the block given to Net::HTTP#request (or one of its wrappers);
  # it may then be used both inside and after the block:
  #
  #   stream = nil
  #   http.request(req) do |res|
  #     stream = res.body_stream
  #   end
  #   begin
  #     process(stream.readpartial(16384)) until stream.eof?
  #   ensure
  #     stream.close
  #   end
  #
  # Chunked transfer coding and Content-Encoding (gzip/deflate) are decoded
  # on demand, as the stream is read; the unread remainder of the body is
  # never buffered in memory.
  #
  # While the stream is open, the underlying connection cannot be used for
  # another request.  Call Net::HTTPResponse::BodyStream#close to release
  # the connection; closing a stream that was not fully read discards up to
  # Net::HTTPResponse::BodyStream::DRAIN_LIMIT bytes so that the connection
  # can be reused, and shuts the connection down when the unread remainder
  # is larger.
  #
  # Raises IOError if the body was already read, or if the response is no
  # longer being delivered.
  #
  def body_stream
    return @body_stream if @body_stream
    stream_check
    if @read
      raise IOError, "#{self.class}\#body_stream called after body was read"
    end
    @read = true
    @body_stream = BodyStream.new(self, @socket, @body_exist)
  end

  # Whether the response has a body stream that is still being read.
  def body_stream_open?  #:nodoc: internal use only
    @body_stream ? @body_stream.open? : false
  end

  # Detaches +socket+ from this response once its body stream is closed.
  def body_stream_detached(socket)  #:nodoc: internal use only
    @socket = nil if @socket.equal?(socket)
  end

  # Returns the string response body;
  # note that repeated calls for the unmodified body return a cached string:
  #
  #   path = '/todos/1'
  #   Net::HTTP.start(hostname) do |http|
  #     res = http.get(path)
  #     p res.body
  #     p http.head(path).body # No body.
  #   end
  #
  # Output:
  #
  #   "{\n  \"userId\": 1,\n  \"id\": 1,\n  \"title\": \"delectus aut autem\",\n  \"completed\": false\n}"
  #   nil
  #
  def body
    read_body()
  end

  # Sets the body of the response to the given value.
  def body=(value)
    @body = value
  end

  alias entity body   #:nodoc: obsolete

  private

  # :nodoc:
  def detect_encoding(str, encoding=nil)
    if encoding
    elsif encoding = type_params['charset']
    elsif encoding = check_bom(str)
    else
      encoding = case content_type&.downcase
      when %r{text/x(?:ht)?ml|application/(?:[^+]+\+)?xml}
        /\A<xml[ \t\r\n]+
          version[ \t\r\n]*=[ \t\r\n]*(?:"[0-9.]+"|'[0-9.]*')[ \t\r\n]+
          encoding[ \t\r\n]*=[ \t\r\n]*
          (?:"([A-Za-z][\-A-Za-z0-9._]*)"|'([A-Za-z][\-A-Za-z0-9._]*)')/x =~ str
        encoding = $1 || $2 || Encoding::UTF_8
      when %r{text/html.*}
        sniff_encoding(str)
      end
    end
    return encoding
  end

  # :nodoc:
  def sniff_encoding(str, encoding=nil)
    # the encoding sniffing algorithm
    # http://www.w3.org/TR/html5/parsing.html#determining-the-character-encoding
    if enc = scanning_meta(str)
      enc
    # 6. last visited page or something
    # 7. frequency
    elsif str.ascii_only?
      Encoding::US_ASCII
    elsif str.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      Encoding::UTF_8
    end
    # 8. implementation-defined or user-specified
  end

  # :nodoc:
  def check_bom(str)
    case str.byteslice(0, 2)
    when "\xFE\xFF"
      return Encoding::UTF_16BE
    when "\xFF\xFE"
      return Encoding::UTF_16LE
    end
    if "\xEF\xBB\xBF" == str.byteslice(0, 3)
      return Encoding::UTF_8
    end
    nil
  end

  # :nodoc:
  def scanning_meta(str)
    require 'strscan'
    ss = StringScanner.new(str)
    if ss.scan_until(/<meta[\t\n\f\r ]*/)
      attrs = {} # attribute_list
      got_pragma = false
      need_pragma = nil
      charset = nil

      # step: Attributes
      while attr = get_attribute(ss)
        name, value = *attr
        next if attrs[name]
        attrs[name] = true
        case name
        when 'http-equiv'
          got_pragma = true if value == 'content-type'
        when 'content'
          encoding = extracting_encodings_from_meta_elements(value)
          unless charset
            charset = encoding
          end
          need_pragma = true
        when 'charset'
          need_pragma = false
          charset = value
        end
      end

      # step: Processing
      return if need_pragma.nil?
      return if need_pragma && !got_pragma

      charset = Encoding.find(charset) rescue nil
      return unless charset
      charset = Encoding::UTF_8 if charset == Encoding::UTF_16
      return charset # tentative
    end
    nil
  end

  def get_attribute(ss)
    ss.scan(/[\t\n\f\r \/]*/)
    if ss.peek(1) == '>'
      ss.getch
      return nil
    end
    name = ss.scan(/[^=\t\n\f\r \/>]*/)
    name.downcase!
    raise if name.empty?
    ss.skip(/[\t\n\f\r ]*/)
    if ss.getch != '='
      value = ''
      return [name, value]
    end
    ss.skip(/[\t\n\f\r ]*/)
    case ss.peek(1)
    when '"'
      ss.getch
      value = ss.scan(/[^"]+/)
      value.downcase!
      ss.getch
    when "'"
      ss.getch
      value = ss.scan(/[^']+/)
      value.downcase!
      ss.getch
    when '>'
      value = ''
    else
      value = ss.scan(/[^\t\n\f\r >]+/)
      value.downcase!
    end
    [name, value]
  end

  def extracting_encodings_from_meta_elements(value)
    # http://dev.w3.org/html5/spec/fetching-resources.html#algorithm-for-extracting-an-encoding-from-a-meta-element
    if /charset[\t\n\f\r ]*=(?:"([^"]*)"|'([^']*)'|["']|\z|([^\t\n\f\r ;]+))/i =~ value
      return $1 || $2 || $3
    end
    return nil
  end

  ##
  # Checks for a supported Content-Encoding header and yields an Inflate
  # wrapper for this response's socket when zlib is present.  If the
  # Content-Encoding is not supported or zlib is missing, the plain socket is
  # yielded.
  #
  # If a Content-Range header is present, a plain socket is yielded as the
  # bytes in the range may not be a complete deflate block.

  def inflater # :nodoc:
    return yield @socket unless Net::HTTP::HAVE_ZLIB
    return yield @socket unless @decode_content
    return yield @socket if self['content-range']

    v = self['content-encoding']
    case v&.downcase
    when 'deflate', 'gzip', 'x-gzip' then
      self.delete 'content-encoding'

      inflate_body_io = Inflater.new(@socket)

      begin
        yield inflate_body_io
        success = true
      ensure
        begin
          inflate_body_io.finish
          if self['content-length']
            self['content-length'] = inflate_body_io.bytes_inflated.to_s
          end
        rescue => err
          # Ignore #finish's error if there is an exception from yield
          raise err if success
        end
      end
    when 'none', 'identity' then
      self.delete 'content-encoding'

      yield @socket
    else
      yield @socket
    end
  end

  def read_body_0(dest)
    inflater do |inflate_body_io|
      if chunked?
        read_chunked dest, inflate_body_io
        return
      end

      @socket = inflate_body_io

      # Transfer-Encoding overrides Content-Length, so a body that is not
      # chunk-framed runs until the server closes the connection.
      # See RFC 9112 Section 6.3.
      unless @header['transfer-encoding']
        clen = content_length()
        if clen
          @socket.read clen, dest, @ignore_eof
          return
        end
        clen = range_length()
        if clen
          @socket.read clen, dest
          return
        end
      end
      @socket.read_all dest
    end
  end

  ##
  # read_chunked reads from +@socket+ for chunk-size, chunk-extension, CRLF,
  # etc. and +chunk_data_io+ for chunk-data which may be deflate or gzip
  # encoded.
  #
  # See RFC 2616 section 3.6.1 for definitions

  def read_chunked(dest, chunk_data_io) # :nodoc:
    total = 0
    while true
      line = self.class.read_line(@socket, MAX_RESPONSE_HEADER_LENGTH).chop
      hexlen = line.slice(/[0-9a-fA-F]+/) or
          raise Net::HTTPBadResponse, "wrong chunk size line: #{line}"
      len = hexlen.hex
      break if len == 0
      begin
        chunk_data_io.read len, dest
      ensure
        total += len
        @socket.read 2   # \r\n
      end
    end
    until self.class.read_line(@socket, MAX_RESPONSE_HEADER_LENGTH).chop.empty?
      # none
    end
  end

  def stream_check
    raise IOError, 'attempt to read body out of block' if @socket.nil? || @socket.closed?
  end

  def procdest(dest, block)
    raise ArgumentError, 'both arg and block given for HTTP method' if
      dest and block
    if block
      Net::ReadAdapter.new(block)
    else
      dest || +''
    end
  end

  ##
  # Inflater is a wrapper around Net::BufferedIO that transparently inflates
  # zlib and gzip streams.

  class Inflater # :nodoc:

    ##
    # Creates a new Inflater wrapping +socket+

    def initialize socket
      @socket = socket
      # zlib with automatic gzip detection
      @inflate = Zlib::Inflate.new(32 + Zlib::MAX_WBITS)
    end

    ##
    # Finishes the inflate stream.

    def finish
      return if @inflate.total_in == 0
      @inflate.finish
    end

    ##
    # The number of bytes inflated, used to update the Content-Length of
    # the response.

    def bytes_inflated
      @inflate.total_out
    end

    ##
    # Returns a Net::ReadAdapter that inflates each read chunk into +dest+.
    #
    # This allows a large response body to be inflated without storing the
    # entire body in memory.

    def inflate_adapter(dest)
      if dest.respond_to?(:set_encoding)
        dest.set_encoding(Encoding::ASCII_8BIT)
      elsif dest.respond_to?(:force_encoding)
        dest.force_encoding(Encoding::ASCII_8BIT)
      end
      block = proc do |compressed_chunk|
        @inflate.inflate(compressed_chunk) do |chunk|
          compressed_chunk.clear
          dest << chunk
        end
      end

      Net::ReadAdapter.new(block)
    end

    ##
    # Reads +clen+ bytes from the socket, inflates them, then writes them to
    # +dest+.  +ignore_eof+ is passed down to Net::BufferedIO#read
    #
    # Unlike Net::BufferedIO#read, this method returns more than +clen+ bytes.
    # At this time there is no way for a user of Net::HTTPResponse to read a
    # specific number of bytes from the HTTP response body, so this internal
    # API does not return the same number of bytes as were requested.
    #
    # See https://bugs.ruby-lang.org/issues/6492 for further discussion.

    def read clen, dest, ignore_eof = false
      temp_dest = inflate_adapter(dest)

      @socket.read clen, temp_dest, ignore_eof
    end

    ##
    # Reads the rest of the socket, inflates it, then writes it to +dest+.

    def read_all dest
      temp_dest = inflate_adapter(dest)

      @socket.read_all temp_dest
    end

  end


  ##
  # BodyStream is a read handle for a response body, returned by
  # Net::HTTPResponse#body_stream.  It serves the decoded body in fragments
  # through #readpartial, reading from the underlying connection only as
  # needed.
  #
  # While a BodyStream is open, the connection it belongs to cannot start
  # another request; call #close to release it.  Closing a stream whose body
  # was not fully read discards up to DRAIN_LIMIT bytes so the connection
  # can be reused, and shuts the connection down when the unread remainder
  # is larger.
  #
  # Returned fragments are binary (ASCII-8BIT) strings.

  class BodyStream

    ##
    # The maximum number of decoded body bytes that #close discards in order
    # to keep the underlying connection reusable; when the unread remainder
    # of the body is larger, the connection is shut down instead.

    DRAIN_LIMIT = 1024 * 1024 # 1 MiB

    READ_CHUNK = 1024 * 16 #:nodoc: internal use only

    def initialize(response, socket, body_exist) #:nodoc: internal use only
      @response = response
      @socket = socket
      @ignore_eof = response.ignore_eof
      @out = +''.b
      @decoder_eof = false
      @connection_broken = false
      @closed = false
      @on_close = nil

      if !body_exist
        @framing = :empty
      elsif response.chunked?
        @framing = :chunked
        @chunk_remaining = 0
      elsif !response['transfer-encoding'] &&
            (length = response.content_length || response.range_length)
        # Transfer-Encoding overrides Content-Length, so a body that is not
        # chunk-framed runs until the server closes the connection.
        # See RFC 9112 Section 6.3.
        @framing = :length
        @length_remaining = length
      else
        @framing = :close
      end

      @inflate = nil
      if Net::HTTP::HAVE_ZLIB && response.decode_content &&
         !response['content-range']
        case response['content-encoding']&.downcase
        when 'deflate', 'gzip', 'x-gzip'
          response.delete 'content-encoding'
          @inflate = Zlib::Inflate.new(32 + Zlib::MAX_WBITS)
        when 'none', 'identity'
          response.delete 'content-encoding'
        end
      end
    end

    # Reads at most +maxlen+ bytes of the decoded body, blocking until at
    # least one byte is available, and returns them as a binary string.
    #
    # When +outbuf+ is given, the fragment is stored into it and +outbuf+ is
    # returned: a String is replaced (like IO#readpartial), any other object
    # is appended to via <tt><<</tt>.  The stream never closes +outbuf+;
    # closing it (if it is an IO) is the caller's responsibility.
    #
    # Raises EOFError when the end of the body is reached, and IOError when
    # the stream is closed.
    #
    def readpartial(maxlen, outbuf = nil)
      raise ArgumentError, "negative length #{maxlen} given" if maxlen < 0
      raise IOError, 'closed response body stream' if closed?
      return +''.b if maxlen.zero?

      begin
        fill_decoded(maxlen)
      rescue => exception
        abort_connection
        raise
      end

      raise EOFError, 'end of response body reached' if @out.empty?

      chunk = @out.slice!(0, maxlen)
      if outbuf
        if outbuf.respond_to?(:replace)
          outbuf.replace(chunk)
        else
          outbuf << chunk
        end
        outbuf
      else
        chunk
      end
    end

    # Returns true when the whole body has been decoded and no buffered
    # bytes remain; may read from the connection to find out.  Raises IOError
    # when the stream is closed.
    #
    def eof?
      raise IOError, 'closed response body stream' if closed?
      return false unless @out.empty?
      return true if @decoder_eof

      begin
        fill_decoded(1)
      rescue => exception
        abort_connection
        raise
      end
      @decoder_eof && @out.empty?
    end

    # Closes the stream and releases the underlying connection.
    #
    # When the body was not fully read, up to DRAIN_LIMIT bytes of the
    # unread remainder are discarded so that the connection can be reused;
    # when the remainder is larger (or cannot be read), the connection is
    # shut down instead.  Does nothing when the stream is already closed.
    #
    def close
      return if @closed
      @closed = true
      reusable = false
      begin
        reusable = drain
      rescue StandardError
        # The remainder of the body could not be drained.
      end
      begin
        @socket.close unless reusable || @socket.closed?
      ensure
        detach
        @on_close&.call(reusable)
      end
      nil
    end

    # Returns true if the stream is closed.
    def closed?
      @closed
    end

    # Whether the stream can still serve bytes from the connection.
    def open?  #:nodoc: internal use only
      !@closed && !@socket.closed?
    end

    # Sets the callback invoked with the reusability of the connection when
    # the stream is closed.
    def on_close=(callback)  #:nodoc: internal use only
      @on_close = callback
    end

    private

    def fill_decoded(maxlen)
      while @out.bytesize < maxlen && !@decoder_eof
        raw = read_raw(READ_CHUNK)
        if raw.nil?
          finish_decoder
        elsif @inflate
          @out << @inflate.inflate(raw)
        else
          @out << raw
        end
      end
    end

    def finish_decoder
      if @inflate
        @out << @inflate.finish if @inflate.total_in > 0
        if @response['content-length']
          @response['content-length'] = @inflate.total_out.to_s
        end
      end
      @decoder_eof = true
    end

    # Reads up to +maxlen+ bytes of the raw (still content-encoded) body,
    # or returns nil when the body is exhausted.
    def read_raw(maxlen)
      case @framing
      when :empty
        nil
      when :length
        return nil if @length_remaining <= 0
        length = [maxlen, @length_remaining].min
        buffer = @socket.read(length, +''.b, @ignore_eof)
        @connection_broken = true if buffer.bytesize < length
        @length_remaining -= buffer.bytesize
        buffer.empty? ? nil : buffer
      when :close
        buffer = @socket.read(maxlen, +''.b, true)
        buffer.empty? ? nil : buffer
      when :chunked
        read_chunk_raw(maxlen)
      end
    end

    def read_chunk_raw(maxlen)
      loop do
        if @chunk_remaining > 0
          length = [maxlen, @chunk_remaining].min
          buffer = @socket.read(length, +''.b, @ignore_eof)
          @connection_broken = true if buffer.bytesize < length
          @chunk_remaining -= buffer.bytesize
          @socket.read(2) if @chunk_remaining <= 0   # CRLF
          return buffer.empty? ? nil : buffer
        end
        line = Net::HTTPResponse.read_line(@socket, MAX_RESPONSE_HEADER_LENGTH).chop
        hexlen = line.slice(/[0-9a-fA-F]+/) or
          raise Net::HTTPBadResponse, "wrong chunk size line: #{line}"
        length = hexlen.hex
        if length.zero?
          until Net::HTTPResponse.read_line(@socket, MAX_RESPONSE_HEADER_LENGTH).chop.empty?
            # none
          end
          return nil
        end
        @chunk_remaining = length
      end
    end

    # Discards the unread remainder of the body and returns whether the
    # connection is reusable afterwards.
    def drain
      drained = 0
      until @decoder_eof
        fill_decoded(READ_CHUNK)
        drained += @out.bytesize
        @out.clear
        return false if drained > DRAIN_LIMIT
      end
      !@connection_broken
    end

    def abort_connection
      return if @closed
      @closed = true
      begin
        @socket.close unless @socket.closed?
      ensure
        detach
        @on_close&.call(false)
      end
    end

    def detach
      @response.body_stream_detached(@socket)
    end

  end

end
