# This is a private class used internally by the library. It should not
# be called by user code.
class Net::LDAP::Connection #:nodoc:
  include Net::LDAP::Instrumentation

  # Seconds before failing for socket connect timeout
  DefaultConnectTimeout = 5

  LdapVersion = 3

  # BER syntax for the RFC 5805 Start/End Transaction response values. The
  # transaction values are wrapped in OCTET STRINGs whose context tags are
  # not covered by Net::LDAP::AsnSyntax, so they are parsed explicitly here.
  #
  # StartTransactionResponseValue ::= SEQUENCE {
  #   responseName [10] OCTET STRING }
  #
  # EndTransactionResponseValue ::= SEQUENCE {
  #   messageID [0] MessageID OPTIONAL,
  #   updates   [1] SEQUENCE OF UpdateControl OPTIONAL }
  #
  # UpdateControl ::= SEQUENCE {
  #   messageID MessageID,
  #   controls  [0] Controls }
  tx_primitive = { 0 => :integer, 1 => :boolean, 10 => :string }
  tx_constructed = { 0 => :array, 1 => :array }
  TransactionSyntax = Net::BER.compile_syntax(
    :universal => {
      :primitive => {
        1 => :boolean, 2 => :integer, 4 => :string, 6 => :oid,
      },
      :constructed => { 16 => :array, 17 => :array },
    },
    :context_specific => {
      :primitive => tx_primitive,
      :constructed => tx_constructed,
    }
  )

  # Initialize a connection to an LDAP server
  #
  # :server
  #   :hosts   Array of tuples specifying host, port
  #   :host    host
  #   :port    port
  #   :socket  prepared socket
  #
  def initialize(server = {})
    @server = server
    @instrumentation_service = server[:instrumentation_service]

    # Allows tests to parameterize what socket class to use
    @socket_class = server.fetch(:socket_class, DefaultSocket)

    # Set to a Net::LDAP::Transaction while an RFC 5805 transaction is open on
    # this connection. #thread_owner records which thread pinned the
    # connection; other threads are refused access for the lifetime of the
    # transaction.
    @transaction = nil
    @thread_owner = nil

    yield self if block_given?
  end

  # Internal: The RFC 5805 transaction currently open on this connection, or
  # nil when no transaction is in progress.
  attr_reader :transaction

  # Internal: True while a transaction is pinning this connection.
  def transaction?
    !@transaction.nil?
  end

  # Internal: Refuses the connection to any thread other than the one that
  # opened the active transaction. Called by #write so an unrelated request
  # can never be multiplexed onto a connection that is bound to a
  # transaction.
  def assert_transaction_owner!
    return unless @transaction
    unless Thread.current == @thread_owner
      raise Net::LDAP::TransactionInProgressError,
            "an LDAP transaction is in progress on this connection; " \
            "operations inside the block must run on the originating thread"
    end
  end

  def socket_class=(socket_class)
    @socket_class = socket_class
  end

  def prepare_socket(server, timeout=nil, hostname='127.0.0.1')
    socket = server[:socket]
    encryption = server[:encryption]

    @conn = socket
    setup_encryption(encryption, timeout, hostname) if encryption
  end

  def open_connection(server)
    hosts = server[:hosts]
    encryption = server[:encryption]

    timeout = server[:connect_timeout] || DefaultConnectTimeout
    socket_opts = {
      connect_timeout: timeout,
    }

    errors = []
    hosts.each do |host, port|
      begin
        prepare_socket(server.merge(socket: @socket_class.new(host, port, socket_opts)), timeout, host)
        if encryption
          if encryption[:tls_options] &&
             encryption[:tls_options][:verify_mode] &&
             encryption[:tls_options][:verify_mode] == OpenSSL::SSL::VERIFY_NONE
            warn "not verifying SSL hostname of LDAPS server '#{host}:#{port}'"
          else
            @conn.post_connection_check(host)
          end
        end
        return
      rescue Net::LDAP::Error, SocketError, SystemCallError,
             OpenSSL::SSL::SSLError => e
        # Ensure the connection is closed in the event a setup failure.
        close
        errors << [e, host, port]
      end
    end

    raise Net::LDAP::ConnectionError.new(errors)
  end

  module GetbyteForSSLSocket
    def getbyte
      c = getc
      c && c.ord
    end
  end

  module FixSSLSocketSyncClose
    def close
      super
      io.close
    end
  end

  def self.wrap_with_ssl(io, tls_options = {}, timeout=nil, hostname=nil)
    raise Net::LDAP::NoOpenSSLError, "OpenSSL is unavailable" unless Net::LDAP::HasOpenSSL

    ctx = OpenSSL::SSL::SSLContext.new

    # By default, we do not verify certificates. For a 1.0 release, this should probably be changed at some point.
    # See discussion in https://github.com/ruby-ldap/ruby-net-ldap/pull/161
    ctx.set_params(tls_options) unless tls_options.empty?

    conn = OpenSSL::SSL::SSLSocket.new(io, ctx)
    conn.hostname = hostname

    begin
      if timeout
        conn.connect_nonblock
      else
        conn.connect
      end
    rescue IO::WaitReadable
      raise Errno::ETIMEDOUT, "OpenSSL connection read timeout" unless
        IO.select([conn], nil, nil, timeout)
      retry
    rescue IO::WaitWritable
      raise Errno::ETIMEDOUT, "OpenSSL connection write timeout" unless
        IO.select(nil, [conn], nil, timeout)
      retry
    end

    # Doesn't work:
    # conn.sync_close = true

    conn.extend(GetbyteForSSLSocket) unless conn.respond_to?(:getbyte)
    conn.extend(FixSSLSocketSyncClose)

    conn
  end

  #--
  # Helper method called only from prepare_socket or open_connection, and only
  # after we have a successfully-opened @conn instance variable, which is a TCP
  # connection.  Depending on the received arguments, we establish SSL,
  # potentially replacing the value of @conn accordingly. Don't generate any
  # errors here if no encryption is requested. DO raise Net::LDAP::Error objects
  # if encryption is requested and we have trouble setting it up. That includes
  # if OpenSSL is not set up on the machine. (Question: how does the Ruby
  # OpenSSL wrapper react in that case?) DO NOT filter exceptions raised by the
  # OpenSSL library. Let them pass back to the user. That should make it easier
  # for us to debug the problem reports. Presumably (hopefully?) that will also
  # produce recognizable errors if someone tries to use this on a machine
  # without OpenSSL.
  #
  # The simple_tls method is intended as the simplest, stupidest, easiest
  # solution for people who want nothing more than encrypted comms with the
  # LDAP server. It doesn't do any server-cert validation and requires
  # nothing in the way of key files and root-cert files, etc etc. OBSERVE:
  # WE REPLACE the value of @conn, which is presumed to be a connected
  # TCPSocket object.
  #
  # The start_tls method is supported by many servers over the standard LDAP
  # port. It does not require an alternative port for encrypted
  # communications, as with simple_tls. Thanks for Kouhei Sutou for
  # generously contributing the :start_tls path.
  #++
  def setup_encryption(args, timeout=nil, hostname=nil)
    args[:tls_options] ||= {}
    case args[:method]
    when :simple_tls
      @conn = self.class.wrap_with_ssl(@conn, args[:tls_options], timeout, hostname)
      # additional branches requiring server validation and peer certs, etc.
      # go here.
    when :start_tls
      message_id = next_msgid
      request    = [
        Net::LDAP::StartTlsOid.to_ber_contextspecific(0),
      ].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

      write(request, nil, message_id)
      pdu = queued_read(message_id)

      if pdu.nil? || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
        raise Net::LDAP::NoStartTLSResultError, "no start_tls result"
      end

      raise Net::LDAP::StartTLSError,
            "start_tls failed: #{pdu.result_code}" unless pdu.result_code.zero?
      @conn = self.class.wrap_with_ssl(@conn, args[:tls_options], timeout, hostname)
    else
      raise Net::LDAP::EncMethodUnsupportedError, "unsupported encryption method #{args[:method]}"
    end
  end

  #--
  # This is provided as a convenience method to make sure a connection
  # object gets closed without waiting for a GC to happen. Clients shouldn't
  # have to call it, but perhaps it will come in handy someday.
  #++
  def close
    return if !defined?(@conn) || @conn.nil?
    @conn.close
    @conn = nil
  end

  # Internal: Reads messages by ID from a queue, falling back to reading from
  # the connected socket until a message matching the ID is read. Any messages
  # with mismatched IDs gets queued for subsequent reads by the origin of that
  # message ID.
  #
  # Returns a Net::LDAP::PDU object or nil.
  def queued_read(message_id)
    if pdu = message_queue[message_id].shift
      return pdu
    end

    # read messages until we have a match for the given message_id
    while pdu = read
      return pdu if pdu.message_id == message_id

      message_queue[pdu.message_id].push pdu
      next
    end

    pdu
  end

  # Internal: The internal queue of messages, read from the socket, grouped by
  # message ID.
  #
  # Used by `queued_read` to return messages sent by the server with the given
  # ID. If no messages are queued for that ID, `queued_read` will `read` from
  # the socket and queue messages that don't match the given ID for other
  # readers.
  #
  # Returns the message queue Hash.
  def message_queue
    @message_queue ||= Hash.new do |hash, key|
      hash[key] = []
    end
  end

  # Internal: Reads and parses data from the configured connection.
  #
  # - syntax: the BER syntax to use to parse the read data with
  #
  # Returns parsed Net::LDAP::PDU object.
  def read(syntax = Net::LDAP::AsnSyntax)
    ber_object =
      instrument "read.net_ldap_connection", :syntax => syntax do |payload|
        socket.read_ber(syntax) do |id, content_length|
          payload[:object_type_id] = id
          payload[:content_length] = content_length
        end
      end

    return unless ber_object

    instrument "parse_pdu.net_ldap_connection" do |payload|
      pdu = payload[:pdu]  = Net::LDAP::PDU.new(ber_object)

      payload[:message_id] = pdu.message_id
      payload[:app_tag]    = pdu.app_tag

      pdu
    end
  end
  private :read

  # Internal: Write a BER formatted packet with the next message id to the
  # configured connection.
  #
  # - request: required BER formatted request
  # - controls: optional BER formatted controls
  #
  # Returns the return value from writing to the connection, which in some
  # cases is the Integer number of bytes written to the socket.
  def write(request, controls = nil, message_id = next_msgid)
    assert_transaction_owner!
    instrument "write.net_ldap_connection" do |payload|
      packet = [message_id.to_ber, request, controls].compact.to_ber_sequence
      payload[:content_length] = socket.write(packet)
    end
  end
  private :write

  def next_msgid
    @msgid ||= 0
    @msgid += 1
  end

  def bind(auth)
    instrument "bind.net_ldap_connection" do |payload|
      payload[:method] = meth = auth[:method]
      adapter = Net::LDAP::AuthAdapter[meth]
      adapter.new(self).bind(auth)
    end
  end

  #--
  # Allow the caller to specify a sort control
  #
  # The format of the sort control needs to be:
  #
  # :sort_control => ["cn"]  # just a string
  # or
  # :sort_control => [["cn", "matchingRule", true]] #attribute, matchingRule, direction (true / false)
  # or
  # :sort_control => ["givenname","sn"] #multiple strings or arrays
  #
  def encode_sort_controls(sort_definitions)
    return sort_definitions unless sort_definitions

    sort_control_values = sort_definitions.map do |control|
      control = Array(control) # if there is only an attribute name as a string then infer the orderinrule and reverseorder
      control[0] = String(control[0]).to_ber,
      control[1] = String(control[1]).to_ber,
      control[2] = (control[2] == true).to_ber
      control.to_ber_sequence
    end
    [
      Net::LDAP::LDAPControls::SORT_REQUEST.to_ber,
      false.to_ber,
      sort_control_values.to_ber_sequence.to_s.to_ber,
    ].to_ber_sequence
  end

  #--
  # Alternate implementation, this yields each search entry to the caller as
  # it are received.
  #
  # TODO: certain search parameters are hardcoded.
  # TODO: if we mis-parse the server results or the results are wrong, we
  # can block forever. That's because we keep reading results until we get a
  # type-5 packet, which might never come. We need to support the time-limit
  # in the protocol.
  #++
  def search(args = nil)
    args ||= {}

    # filtering, scoping, search base
    # filter: https://tools.ietf.org/html/rfc4511#section-4.5.1.7
    # base:   https://tools.ietf.org/html/rfc4511#section-4.5.1.1
    # scope:  https://tools.ietf.org/html/rfc4511#section-4.5.1.2
    filter = args[:filter] || Net::LDAP::Filter.eq("objectClass", "*")
    base   = args[:base]
    scope  = args[:scope] || Net::LDAP::SearchScope_WholeSubtree

    # attr handling
    # attrs:      https://tools.ietf.org/html/rfc4511#section-4.5.1.8
    # attrs_only: https://tools.ietf.org/html/rfc4511#section-4.5.1.6
    attrs  = Array(args[:attributes])
    attrs_only = args[:attributes_only] == true

    # references
    # refs:  https://tools.ietf.org/html/rfc4511#section-4.5.3
    # deref: https://tools.ietf.org/html/rfc4511#section-4.5.1.3
    refs   = args[:return_referrals] == true
    deref  = args[:deref] || Net::LDAP::DerefAliases_Never

    # limiting, paging, sorting
    # size: https://tools.ietf.org/html/rfc4511#section-4.5.1.4
    # time: https://tools.ietf.org/html/rfc4511#section-4.5.1.5
    size   = args[:size].to_i
    time   = args[:time].to_i
    paged  = args[:paged_searches_supported]
    sort   = args.fetch(:sort_controls, false)

    # arg validation
    raise ArgumentError, "search base is required" unless base
    raise ArgumentError, "invalid search-size" unless size >= 0
    raise ArgumentError, "invalid search scope" unless Net::LDAP::SearchScopes.include?(scope)
    raise ArgumentError, "invalid alias dereferencing value" unless Net::LDAP::DerefAliasesArray.include?(deref)

    # arg transforms
    filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
    ber_attrs = attrs.map { |attr| attr.to_s.to_ber }
    ber_sort  = encode_sort_controls(sort)

    # An interesting value for the size limit would be close to A/D's
    # built-in page limit of 1000 records, but openLDAP newer than version
    # 2.2.0 chokes on anything bigger than 126. You get a silent error that
    # is easily visible by running slapd in debug mode. Go figure.
    #
    # Changed this around 06Sep06 to support a caller-specified search-size
    # limit. Because we ALWAYS do paged searches, we have to work around the
    # problem that it's not legal to specify a "normal" sizelimit (in the
    # body of the search request) that is larger than the page size we're
    # requesting. Unfortunately, I have the feeling that this will break
    # with LDAP servers that don't support paged searches!!!
    #
    # (Because we pass zero as the sizelimit on search rounds when the
    # remaining limit is larger than our max page size of 126. In these
    # cases, I think the caller's search limit will be ignored!)
    #
    # CONFIRMED: This code doesn't work on LDAPs that don't support paged
    # searches when the size limit is larger than 126. We're going to have
    # to do a root-DSE record search and not do a paged search if the LDAP
    # doesn't support it. Yuck.
    rfc2696_cookie = [126, ""]
    result_pdu = nil
    n_results = 0

    message_id = next_msgid

    instrument "search.net_ldap_connection",
               message_id: message_id,
               filter:     filter,
               base:       base,
               scope:      scope,
               size:       size,
               time:       time,
               sort:       sort,
               referrals:  refs,
               deref:      deref,
               attributes: attrs do |payload|
      loop do
        # should collect this into a private helper to clarify the structure
        query_limit = 0
        if size > 0
          query_limit = if paged
                          (((size - n_results) < 126) ? (size - n_results) : 0)
                        else
                          size
                        end
        end

        request = [
          base.to_ber,
          scope.to_ber_enumerated,
          deref.to_ber_enumerated,
          query_limit.to_ber, # size limit
          time.to_ber,
          attrs_only.to_ber,
          filter.to_ber,
          ber_attrs.to_ber_sequence,
        ].to_ber_appsequence(Net::LDAP::PDU::SearchRequest)

        # rfc2696_cookie sometimes contains binary data from Microsoft Active Directory
        # this breaks when calling to_ber. (Can't force binary data to UTF-8)
        # we have to disable paging (even though server supports it) to get around this...

        user_controls = args.fetch(:controls, [])
        controls = []
        controls <<
          [
            Net::LDAP::LDAPControls::PAGED_RESULTS.to_ber,
            # Criticality MUST be false to interoperate with normal LDAPs.
            false.to_ber,
            rfc2696_cookie.map(&:to_ber).to_ber_sequence.to_s.to_ber,
          ].to_ber_sequence if paged
        controls << ber_sort if ber_sort
        if controls.empty? && user_controls.empty?
          controls = nil
        else
          controls += user_controls
          controls = controls.to_ber_contextspecific(0)
        end

        write(request, controls, message_id)

        result_pdu = nil
        controls = []

        while pdu = queued_read(message_id)
          case pdu.app_tag
          when Net::LDAP::PDU::SearchReturnedData
            n_results += 1
            yield pdu.search_entry if block_given?
          when Net::LDAP::PDU::SearchResultReferral
            if refs
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
          when Net::LDAP::PDU::SearchResult
            result_pdu = pdu
            controls = pdu.result_controls
            if refs && pdu.result_code == Net::LDAP::ResultCodeReferral
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
            break
          else
            raise Net::LDAP::ResponseTypeInvalidError, "invalid response-type in search: #{pdu.app_tag}"
          end
        end

        if result_pdu.nil?
          raise Net::LDAP::ResponseMissingOrInvalidError, "response missing"
        end

        # count number of pages of results
        payload[:page_count] ||= 0
        payload[:page_count]  += 1

        # When we get here, we have seen a type-5 response. If there is no
        # error AND there is an RFC-2696 cookie, then query again for the next
        # page of results. If not, we're done. Don't screw this up or we'll
        # break every search we do.
        #
        # Noticed 02Sep06, look at the read_ber call in this loop, shouldn't
        # that have a parameter of AsnSyntax? Does this just accidentally
        # work? According to RFC-2696, the value expected in this position is
        # of type OCTET STRING, covered in the default syntax supported by
        # read_ber, so I guess we're ok.
        more_pages = false
        if result_pdu.result_code == Net::LDAP::ResultCodeSuccess and controls
          controls.each do |c|
            if c.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
              # just in case some bogus server sends us more than 1 of these.
              more_pages = false
              if c.value and c.value.length > 0
                cookie = c.value.read_ber[1]
                if cookie and cookie.length > 0
                  rfc2696_cookie[1] = cookie
                  more_pages = true
                end
              end
            end
          end
        end

        break unless more_pages
      end # loop

      # track total result count
      payload[:result_count] = n_results

      result_pdu || OpenStruct.new(:status => :failure, :result_code => Net::LDAP::ResultCodeOperationsError, :message => "Invalid search")
    end # instrument
  ensure

    # clean up message queue for this search
    messages = message_queue.delete(message_id)

    # in the exceptional case some messages were *not* consumed from the queue,
    # instrument the event but do not fail.
    if !messages.nil? && !messages.empty?
      instrument "search_messages_unread.net_ldap_connection",
                 message_id: message_id, messages: messages
    end
  end

  MODIFY_OPERATIONS = { #:nodoc:
    :add => 0,
    :delete => 1,
    :replace => 2,
  }

  def self.modify_ops(operations)
    ops = []
    if operations
      operations.each do |op, attrib, values|
        # TODO, fix the following line, which gives a bogus error if the
        # opcode is invalid.
        op_ber = MODIFY_OPERATIONS[op.to_sym].to_ber_enumerated
        values = [values].flatten.map { |v| v.to_ber if v }.to_ber_set
        values = [attrib.to_s.to_ber, values].to_ber_sequence
        ops << [op_ber, values].to_ber
      end
    end
    ops
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  # TODO: We're throwing an exception here on empty DN. Should return a
  # proper error instead, probaby from farther up the chain.
  # TODO: If the user specifies a bogus opcode, we'll throw a confusing
  # error here ("to_ber_enumerated is not defined on nil").
  #++
  def modify(args)
    modify_dn = args[:dn] or raise "Unable to modify empty DN"
    ops = self.class.modify_ops args[:operations]

    message_id = next_msgid
    request    = [
      modify_dn.to_ber,
      ops.to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::ModifyRequest)

    controls = if transaction?
                 with_transaction_controls(args.fetch(:controls, nil))
               else
                 args.fetch(:controls, nil)&.to_ber_contextspecific(0)
               end

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ModifyResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    record_transaction_operation(message_id, :modify, args, pdu)
    pdu
  end

  ##
  # Password Modify
  #
  # http://tools.ietf.org/html/rfc3062
  #
  # passwdModifyOID OBJECT IDENTIFIER ::= 1.3.6.1.4.1.4203.1.11.1
  #
  # PasswdModifyRequestValue ::= SEQUENCE {
  #   userIdentity    [0]  OCTET STRING OPTIONAL
  #   oldPasswd       [1]  OCTET STRING OPTIONAL
  #   newPasswd       [2]  OCTET STRING OPTIONAL }
  #
  # PasswdModifyResponseValue ::= SEQUENCE {
  #   genPasswd       [0]     OCTET STRING OPTIONAL }
  #
  # Encoded request:
  #
  #   00\x02\x01\x02w+\x80\x171.3.6.1.4.1.4203.1.11.1\x81\x100\x0E\x81\x05old\x82\x05new
  #
  def password_modify(args)
    dn = args[:dn]
    raise ArgumentError, 'DN is required' if !dn || dn.empty?

    ext_seq = [Net::LDAP::PasswdModifyOid.to_ber_contextspecific(0)]

    pwd_seq = []
    pwd_seq << dn.to_ber(0x80)
    pwd_seq << args[:old_password].to_ber(0x81) unless args[:old_password].nil?
    pwd_seq << args[:new_password].to_ber(0x82) unless args[:new_password].nil?
    ext_seq << pwd_seq.to_ber_sequence.to_ber(0x81)

    request = ext_seq.to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid

    write(request, nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  # Unlike other operation-methods in this class, we return a result hash
  # rather than a simple result number. This is experimental, and eventually
  # we'll want to do this with all the others. The point is to have access
  # to the error message and the matched-DN returned by the server.
  #++
  def add(args)
    add_dn = args[:dn] or raise Net::LDAP::EmptyDNError, "Unable to add empty DN"
    add_attrs = []
    a = args[:attributes] and a.each do |k, v|
      add_attrs << [k.to_s.to_ber, Array(v).map(&:to_ber).to_ber_set].to_ber_sequence
    end

    message_id = next_msgid
    request    = [add_dn.to_ber, add_attrs.to_ber_sequence].to_ber_appsequence(Net::LDAP::PDU::AddRequest)

    controls = if transaction?
                 with_transaction_controls(args.fetch(:controls, nil))
               else
                 args.fetch(:controls, nil)&.to_ber_contextspecific(0)
               end

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::AddResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    record_transaction_operation(message_id, :add, args, pdu)
    pdu
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  #++
  def rename(args)
    old_dn = args[:olddn] or raise "Unable to rename empty DN"
    new_rdn = args[:newrdn] or raise "Unable to rename to empty RDN"
    delete_attrs = args[:delete_attributes] ? true : false
    new_superior = args[:new_superior]

    message_id = next_msgid
    request    = [old_dn.to_ber, new_rdn.to_ber, delete_attrs.to_ber]
    request   << new_superior.to_ber_contextspecific(0) unless new_superior == nil

    controls = with_transaction_controls(nil) if transaction?

    write(request.to_ber_appsequence(Net::LDAP::PDU::ModifyRDNRequest), controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ModifyRDNResponse
      raise Net::LDAP::ResponseMissingOrInvalidError.new "response missing or invalid"
    end

    record_transaction_operation(message_id, :rename, args, pdu)
    pdu
  end

  #--
  # TODO, need to support a time limit, in case the server fails to respond.
  #++
  def delete(args)
    dn = args[:dn] or raise "Unable to delete empty DN"
    if @transaction
      user_controls = args.include?(:control_codes) ? args[:control_codes].to_ber_control : nil
      controls = with_transaction_controls(user_controls)
    else
      controls = args.include?(:control_codes) ? args[:control_codes].to_ber_control : nil #use nil so we can compact later
    end
    message_id = next_msgid
    request    = dn.to_s.to_ber_application_string(Net::LDAP::PDU::DeleteRequest)

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::DeleteResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    record_transaction_operation(message_id, :delete, args, pdu)
    pdu
  end

  def ldapwhoami
    ext_seq = [Net::LDAP::WhoamiOid.to_ber_contextspecific(0)]
    request = ext_seq.to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid

    write(request, nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  # Internal: Send the RFC 5805 Start Transaction extended request.
  #
  # Returns the newly opened Net::LDAP::Transaction, whose opaque server
  # identifier will be attached to every subsequent update on this
  # connection until #end_transaction is called.
  def start_transaction
    request = [
      Net::LDAP::StartTransactionOid.to_ber_contextspecific(0),
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid
    write(request, nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
      raise Net::LDAP::ResponseMissingOrInvalidError,
            "Start Transaction response missing or invalid"
    end

    unless pdu.success?
      raise Net::LDAP::TransactionStartError,
            "Start Transaction failed: #{pdu.error_message} (#{pdu.result_code})"
    end

    identifier = parse_start_transaction_identifier(pdu)
    if identifier.nil?
      raise Net::LDAP::TransactionStartError,
            "Start Transaction response did not include a transaction identifier"
    end

    @transaction = Net::LDAP::Transaction.new(identifier, message_id)
    @thread_owner = Thread.current
    @transaction
  end

  # Internal: Send the RFC 5805 End Transaction extended request.
  #
  # commit :: +true+ commits the transaction, +false+ aborts (cancels) it.
  #
  # Returns the transaction with #end_pdu populated. Raises
  # Net::LDAP::TransactionResultUnknownError if no End Transaction response
  # is received; the caller must not replay the block in that case.
  def end_transaction(commit)
    transaction = @transaction
    raise Net::LDAP::TransactionError, "no transaction is in progress" unless transaction

    # EndTransactionRequestValue ::= SEQUENCE {
    #   commit  BOOLEAN DEFAULT FALSE,
    #   messageID MessageID }
    #
    # INTEGER has no context-specific BER helper in net-ber, so emit the
    # [0] primitive tag byte explicitly around the INTEGER value bytes.
    message_id_content = integer_content_bytes(transaction.start_message_id)
    # BOOLEAN likewise has only the universal encoder; wrap its content in
    # the [1] context-specific primitive tag.
    commit_content = (commit ? "\xFF" : "\x00").b
    request_value = [
      [0x80, message_id_content.length].pack("CC") + message_id_content,
      [0x81, 1].pack("CC") + commit_content,
    ].to_ber_contextspecific(1)
    request = [
      Net::LDAP::EndTransactionOid.to_ber_contextspecific(0),
      request_value,
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid
    transaction.end_message_id = message_id
    write(request, nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
      raise Net::LDAP::TransactionResultUnknownError.new(
        commit, transaction.operations
      )
    end

    transaction.end_pdu = pdu
    transaction
  ensure
    # The transaction is finished on the wire either way; release the
    # connection for other (non-transaction) work.
    @transaction = nil
    @thread_owner = nil
  end

  # Internal: Extracts the opaque identifier out of a successful Start
  # Transaction response.
  #
  # The response value is a SEQUENCE wrapping the identifier in a [10]
  # context-specific OCTET STRING.
  def parse_start_transaction_identifier(pdu)
    value = pdu.extended_response
    return nil if value.nil? || value.empty?

    sequence = parse_transaction_value(value)
    return nil unless sequence.is_a?(Array)

    field = sequence.find do |element|
      ber_tag(element) == 0x8a # responseName [10] OCTET STRING
    end
    field.nil? || field.empty? ? nil : field.to_s
  end
  private :parse_start_transaction_identifier

  # Internal: Parses an End Transaction response value into the failed
  # request message ids and the per-update controls returned by the server.
  #
  # Returns a Hash with :message_ids (Array of Integer) and :updates
  # (Array of { :message_id => Integer, :controls => Array<OpenStruct> }).
  def parse_end_transaction_value(pdu)
    result = { :message_ids => [], :updates => [] }
    value = pdu.extended_response
    return result if value.nil? || value.empty?

    sequence = parse_transaction_value(value)
    return result unless sequence.is_a?(Array)

    sequence.each do |field|
      case ber_tag(field)
      when 0x80, 0x02 # messageID [0] MessageID (or a parsed bare INTEGER)
        result[:message_ids] << field.to_i
      when 0xa1 # updates [1] SEQUENCE OF UpdateControl
        Array(field).each do |update|
          next unless update.is_a?(Array)

          message_id = update.find { |element| element.is_a?(Integer) }
          controls_field = update.find { |element| ber_tag(element) == 0xa0 }
          controls = controls_field ? parse_transaction_controls(controls_field) : []
          result[:updates] << { :message_id => message_id, :controls => controls }
        end
      else
        next
      end
    end

    result
  end
  private :parse_end_transaction_value

  # Internal: Reads an RFC 5805 response value. Net::LDAP::PDU may already
  # have decoded the outer context-specific wrappers with the generic LDAP
  # syntax (yielding Arrays and Integers), or the value may still be a raw
  # BER OCTET STRING when parsing a PDU built by other means; accept both.
  def parse_transaction_value(value)
    return value if value.is_a?(Array)

    value.read_ber(TransactionSyntax)
  rescue Net::BER::BerError
    nil
  end
  private :parse_transaction_value

  # Internal: Returns the raw BER tag byte of a parsed element. Elements
  # decoded directly into Ruby Integers/Arrays (universal tags) report the
  # corresponding universal tag.
  def ber_tag(element)
    if element.respond_to?(:ber_identifier)
      element.ber_identifier
    elsif element.is_a?(Integer)
      0x02 # INTEGER
    elsif element.is_a?(Array)
      0x30 # SEQUENCE
    end
  end
  private :ber_tag

  # Internal: Converts a parsed RFC 4511 Controls sequence into the same
  # OpenStruct representation used by Net::LDAP::PDU#parse_controls.
  def parse_transaction_controls(sequence)
    sequence = sequence.read_ber(TransactionSyntax) if sequence.is_a?(String)
    Array(sequence).map do |control|
      o = OpenStruct.new
      o.oid, o.criticality, o.value = control[0], control[1], control[2]
      if o.criticality && o.criticality.is_a?(String)
        o.value = o.criticality
        o.criticality = false
      end
      o
    end
  end
  private :parse_transaction_controls

  # Internal: BER-encodes the RFC 5805 transaction specification control for
  # the open transaction. The criticality is always TRUE and the value is the
  # opaque identifier returned by Start Transaction.
  def transaction_control
    [
      Net::LDAP::LDAPControls::TRANSACTION_SPECIFICATION.to_ber,
      true.to_ber,
      @transaction.identifier.to_ber,
    ].to_ber_sequence
  end
  private :transaction_control

  # Internal: BER content bytes (tag and length excluded) for an Integer.
  def integer_content_bytes(value)
    encoded = value.to_ber
    encoded.byteslice(2, encoded.bytesize - 2)
  end
  private :integer_content_bytes

  # Internal: Builds the RFC 4511 controls field (a constructed [0]
  # envelope wrapping a SEQUENCE OF Control) for the open transaction,
  # prepending the transaction specification control to any user-supplied,
  # already BER-encoded controls SEQUENCE. Returns nil outside a
  # transaction.
  def with_transaction_controls(user_controls)
    return nil unless @transaction

    controls = [transaction_control]
    controls << user_controls unless user_controls.nil?
    controls.to_ber_contextspecific(0)
  end
  private :with_transaction_controls

  # Internal: Records an operation issued as part of the open transaction so
  # the End Transaction response can be mapped back to it.
  def record_transaction_operation(message_id, operation, args, pdu)
    return unless @transaction

    @transaction.record(message_id, operation, args)
    @transaction.record_response(message_id, pdu)
  end
  private :record_transaction_operation

  # Internal: Returns a Socket like object used internally to communicate with
  # LDAP server.
  #
  # Typically a TCPSocket, but can be a OpenSSL::SSL::SSLSocket
  def socket
    return @conn if defined?(@conn) && !@conn.nil?

    # First refactoring uses the existing methods open_connection and
    # prepare_socket to set @conn. Next cleanup would centralize connection
    # handling here.
    if @server[:socket]
      prepare_socket(@server)
    else
      @server[:hosts] = [[@server[:host], @server[:port]]] if @server[:hosts].nil?
      open_connection(@server)
    end

    @conn
  end

  private

  # Wrap around Socket.tcp to normalize with other Socket initializers
  class DefaultSocket
    def self.new(host, port, socket_opts = {})
      Socket.tcp(host, port, **socket_opts)
    end
  end
end # class Connection
