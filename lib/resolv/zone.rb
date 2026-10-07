# frozen_string_literal: true

class Resolv
  class DNS

    ##
    # Reads a DNS master zone file as described in RFC 1035 section 5.1 and
    # turns its text records into the existing Resolv::DNS::Resource objects.
    #
    # Supported syntax:
    # - the +$ORIGIN+, +$TTL+ and +$INCLUDE+ directives,
    # - parenthesized records spanning several lines,
    # - comments (+;+), quoted character-strings and backslash escapes,
    # - records whose owner is omitted (the previous owner is inherited),
    # - relative domain names completed with the current origin,
    # - unknown types and classes kept as RFC 3597 generic records.
    #
    # The reader never opens a path itself.  Included files are fetched with
    # the +resolver+ given to #initialize (a keyword argument or a block), so
    # the caller controls path validation, caching and security.
    #
    #   resolver = proc {|name, origin| File.read(File.join("/var/named", name)) }
    #   zone = Resolv::DNS::Zone.new(File.read("example.zone"),
    #                                origin: "example.org.",
    #                                &resolver)
    #   zone.each_resource do |name, ttl, resource|
    #     p [name, ttl, resource]
    #   end

    class Zone

      BACKSLASH = 92.chr
      private_constant :BACKSLASH

      ##
      # Raised when a zone file cannot be parsed.  #file, #line and #column
      # identify the position where the error was detected; #record is the
      # text of the logical record (continued lines joined) being parsed.

      class ParseError < StandardError
        attr_accessor :file, :line, :column, :record

        def initialize(message, file: nil, line: nil, column: nil, record: nil)
          super(message)
          @file = file
          @line = line
          @column = column
          @record = record
        end
      end

      CLASS_NAMES = {
        "IN" => 1, "CH" => 3, "CHAOS" => 3,
        "HS" => 4, "HESIOD" => 4, "NONE" => 254, "ANY" => 255,
      }
      private_constant :CLASS_NAMES

      TYPE_NAMES = {
        "A" => 1, "NS" => 2, "MD" => 3, "MF" => 4, "CNAME" => 5,
        "SOA" => 6, "MB" => 7, "MG" => 8, "MR" => 9, "NULL" => 10,
        "WKS" => 11, "PTR" => 12, "HINFO" => 13, "MINFO" => 14,
        "MX" => 15, "TXT" => 16, "RP" => 17, "AFSDB" => 18, "X25" => 19,
        "ISDN" => 20, "RT" => 21, "NSAP" => 22, "NSAP-PTR" => 23,
        "SIG" => 24, "KEY" => 25, "PX" => 26, "GPOS" => 27, "AAAA" => 28,
        "LOC" => 29, "NXT" => 30, "SRV" => 33, "NAPTR" => 35, "KX" => 36,
        "CERT" => 37, "DNAME" => 39, "OPT" => 41, "APL" => 42, "DS" => 43,
        "SSHFP" => 44, "IPSECKEY" => 45, "RRSIG" => 46, "NSEC" => 47,
        "DNSKEY" => 48, "DHCID" => 49, "NSEC3" => 50, "NSEC3PARAM" => 51,
        "TLSA" => 52, "SMIMEA" => 53, "HIP" => 55, "NINFO" => 56,
        "CDS" => 59, "CDNSKEY" => 60, "OPENPGPKEY" => 61, "CSYNC" => 62,
        "ZONEMD" => 63, "SVCB" => 64, "HTTPS" => 65, "SPF" => 99,
        "EUI48" => 108, "EUI64" => 109, "TKEY" => 249, "TSIG" => 250,
        "AXFR" => 252, "MAILB" => 253, "MAILA" => 254, "ANY" => 255,
        "URI" => 256, "CAA" => 257,
      }
      private_constant :TYPE_NAMES

      TTL_UNITS = {"W" => 604800, "D" => 86400, "H" => 3600,
                   "M" => 60, "S" => 1}
      private_constant :TTL_UNITS

      Token = Struct.new(:text, :quoted, :line, :column, :at_line_start)
      Entry = Struct.new(:file, :name, :ttl, :resource, :text, :first_line)

      ##
      # Creates a zone reader.  See the class documentation for examples.
      #
      # +source+ is the zone content as a String or an object responding to
      # +each_line+.  +filename+ is used in error messages and include cycle
      # detection; it defaults to +source.path+ when available.
      #
      # +origin+ is the initial origin (a String or Resolv::DNS::Name);
      # relative names are completed with it.  +ttl+ (alias +default_ttl+) is
      # the default TTL used before the first +$TTL+ directive.
      #
      # Included content is fetched through +resolver+ (or the block), called
      # as <tt>resolver.call(name, origin)</tt> where +name+ is the text
      # following +$INCLUDE+ and +origin+ is the origin in effect in the
      # included file.  It must return the content as a String or IO-like
      # object, or <tt>[content, filename]</tt> to also name the file.

      def initialize(source, filename: (source.respond_to?(:path) ? source.path : nil),
                     origin: nil, ttl: nil, default_ttl: nil,
                     resolver: nil, &block)
        @top_filename = filename ? filename.to_s : "(zone)"
        @resolver = resolver || block
        @entries = []
        initial_origin = origin ? coerce_origin(origin) : nil
        initial_ttl = ttl || default_ttl
        initial_ttl = initial_ttl.to_int if initial_ttl
        origin, ttl, = scan(source, @top_filename, initial_origin,
                           initial_ttl, nil, [@top_filename])
        @origin = origin
        @ttl = ttl
      end

      ##
      # The origin in effect after reading the top level file.

      attr_reader :origin

      ##
      # The default TTL (from +$TTL+) in effect after reading the file.

      attr_reader :ttl

      ##
      # Iterates over the records as +[name, ttl, resource]+ triples.  +name+
      # is a Resolv::DNS::Name and +resource+ is a Resolv::DNS::Resource.
      # Returns an Enumerator when no block is given.

      def each_resource
        return enum_for(__method__) unless block_given?
        @entries.each do |entry|
          yield [entry.name, entry.ttl, entry.resource]
        end
        nil
      end
      alias each each_resource

      include Enumerable

      ##
      # Returns the records as an Array of +[name, ttl, resource]+ triples.

      def to_a
        each_resource.to_a
      end

      private

      def scan_error(file, line, column, message)
        ParseError.new(message, file: file, line: line, column: column)
      end

      # Tokenizes one file, appending RR entries to @entries and acting on
      # directives.  origin/ttl/last_owner are local to this file: they are
      # saved for an include and restored afterwards, so the included file's
      # origin, default TTL and inherited owner never leak into the parent.
      def scan(source, file, origin, ttl, last_owner, include_stack)
        tokens = []
        record_lines = []
        record_start = nil
        record_active = false
        first_at_line_start = false
        depth = 0
        in_quote = false
        seg = nil
        seg_quoted = false
        seg_col = nil
        seg_depth = 0
        line_no = 0

        flush = proc do
          unless tokens.empty?
            if tokens.first.text.start_with?("$")
              begin
                origin, ttl, last_owner =
                  run_directive(tokens, file, origin, ttl, last_owner,
                                include_stack)
              rescue ParseError
                raise
              rescue => e
                raise scan_error(file, tokens.first.line,
                                 tokens.first.column, e.message)
              end
            else
              record_text = record_lines.join("\n")
              name, rr_ttl, resource =
                parse_rr(tokens, origin, ttl, last_owner, file,
                         record_start, record_text)
              last_owner = name
              @entries << Entry.new(file, name, rr_ttl, resource,
                                    record_text, record_start)
            end
          end
          tokens = []
          record_lines = []
          record_start = nil
          record_active = false
          first_at_line_start = false
        end

        push_seg = proc do
          if seg
            unless record_active
              first_at_line_start = seg_depth == 0 && seg_col == 1
              record_start = line_no
              record_active = true
            end
            tokens << Token.new(seg, seg_quoted, line_no, seg_col,
                                tokens.empty? ? first_at_line_start : false)
            seg = nil
          end
        end

        source.each_line do |raw_line|
          line_no += 1
          line = raw_line.sub(/\r?\n\z/, "")
          col = 0
          i = 0
          while i < line.length
            ch = line[i]
            col += 1
            case ch
            when BACKSLASH
              if seg.nil?
                seg = String.new
                seg_quoted = in_quote
                seg_col = col
                seg_depth = depth
              end
              seg << ch
              if i + 1 >= line.length
                if depth > 0
                  push_seg.call
                  i += 1
                  next
                end
                raise scan_error(file, line_no, col, "trailing backslash")
              end
              i += 1
              col += 1
              seg << line[i]
            when '"'
              if seg.nil?
                seg = String.new
                seg_quoted = true
                seg_col = col
                seg_depth = depth
              end
              in_quote = !in_quote
            when ";"
              if in_quote
                seg << ch
              else
                push_seg.call
                i = line.length
                next
              end
            when "("
              if in_quote
                seg << ch
              else
                push_seg.call
                depth += 1
              end
            when ")"
              if in_quote
                seg << ch
              elsif depth == 0
                raise scan_error(file, line_no, col, ") without matching (")
              else
                push_seg.call
                depth -= 1
              end
            when " ", "\t"
              if in_quote
                seg << ch
              else
                push_seg.call
              end
            else
              if seg.nil?
                seg = String.new
                seg_quoted = in_quote
                seg_col = col
                seg_depth = depth
              end
              seg << ch
            end
            i += 1
          end

          raise scan_error(file, line_no, col + 1,
                           "unterminated quoted string") if in_quote

          record_lines << line if record_active || depth > 0

          if depth > 0
            push_seg.call
            next
          end

          push_seg.call
          flush.call unless tokens.empty?
        end

        raise scan_error(file, line_no, 1,
                         "unterminated parenthesized expression") if depth > 0
        push_seg.call
        flush.call

        [origin, ttl, last_owner]
      end

      def run_directive(tokens, file, origin, ttl, last_owner, include_stack)
        name = tokens.first.text.upcase
        args = tokens[1..]
        where = [tokens.first.line, tokens.first.column]
        case name
        when "$ORIGIN"
          unless args.length == 1
            raise scan_error(file, *where, "$ORIGIN expects exactly one name")
          end
          origin = resolve_name_text(args.first.text, origin)
        when "$TTL"
          unless args.length == 1
            raise scan_error(file, *where, "$TTL expects exactly one value")
          end
          ttl = parse_ttl(args.first)
        when "$INCLUDE"
          unless (1..2) === args.length
            raise scan_error(file, *where,
                             "$INCLUDE expects a file name and optional origin")
          end
          include_name = unescape_text(args[0].text)
          include_origin = origin
          if args[1]
            include_origin = resolve_name_text(args[1].text, origin)
          end
          origin, ttl, last_owner =
            run_include(include_name, include_origin, origin, ttl,
                        last_owner, include_stack, file, *where)
        else
          raise scan_error(file, *where, "unknown directive #{tokens.first.text}")
        end
        [origin, ttl, last_owner]
      end

      def run_include(name, include_origin, parent_origin, parent_ttl,
                     parent_owner, include_stack, file, line, col)
        unless @resolver
          raise scan_error(file, line, col,
                           "$INCLUDE #{name}: no include resolver was provided")
        end
        content, include_file =
          begin
            result = call_resolver(name, include_origin, file, line, col)
            case result
            when Array
              unless result.length == 2
                raise scan_error(file, line, col,
                  "$INCLUDE #{name}: resolver must return content or [content, filename]")
              end
              result
            else
              [result, name]
            end
          end
        include_file = include_file.to_s
        chain = include_stack + [include_file]
        if include_stack.include?(include_file)
          cycle_chain = chain
          raise scan_error(file, line, col,
                           "$INCLUDE cycle detected: #{cycle_chain.join(" -> ")}")
        end
        # Included files start with no inherited owner.  Parent state is
        # returned unchanged regardless of what happens inside the include.
        scan(content, include_file, include_origin, parent_ttl, nil, chain)
        [parent_origin, parent_ttl, parent_owner]
      end

      def call_resolver(name, origin, file, line, col)
        unless @resolver.respond_to?(:call)
          raise TypeError, "include resolver must respond to #call"
        end
        arity = @resolver.method(:call).arity
        result =
          if arity == 1
            @resolver.call(name)
          else
            @resolver.call(name, origin)
          end
        result
      rescue ParseError
        raise
      rescue => e
        raise scan_error(file, line, col, "$INCLUDE #{name}: #{e.message}")
      end

      # ---- names and character strings ------------------------------------

      def root_origin
        Name.new([], true)
      end

      def coerce_origin(value)
        case value
        when Name then value
        else
          resolve_name_text(value.to_s, root_origin)
        end
      end

      # Decodes the escape at +i+, which points just after the backslash.
      # Returns [byte_string, extra_consumed]: 0 for a single escaped byte,
      # 2 for \DDD and \xHH (the extra two bytes after the first).
      def read_escape(text, i)
        c = text[i]
        if c >= "0" && c <= "9"
          digits = text[i, 3]
          unless digits.length == 3 && digits =~ /\A[0-9]{3}\z/
            raise ArgumentError, "invalid \\DDD escape"
          end
          value = digits.to_i
          unless (0..255) === value
            raise ArgumentError, "\\DDD escape out of range"
          end
          [value.chr.b, 2]
        elsif c == "x" || c == "X"
          hex = text[(i + 1), 2]
          unless hex && hex =~ /\A[0-9A-Fa-f]{2}\z/
            raise ArgumentError, "invalid \\xHH escape"
          end
          [hex.to_i(16).chr.b, 2]
        else
          [c, 0]
        end
      end

      # Splits a raw name token into [labels_as_strings, absolute?].  Dots
      # preceded by a backslash are kept inside their label.
      def split_domain(text)
        labels = []
        label = String.new
        i = 0
        while i < text.length
          ch = text[i]
          if ch == "."
            labels << label
            label = String.new
            i += 1
          elsif ch == BACKSLASH
            if i + 1 >= text.length
              raise ArgumentError, "trailing backslash in name"
            end
            i += 1
            value, extra = read_escape(text, i)
            label << value
            i += 1 + extra
          else
            label << ch
            i += 1
          end
        end
        unless text.end_with?(".") && label.empty?
          labels << label
        end
        absolute = text.end_with?(".")
        if absolute && !labels.empty? && labels.last.empty?
          labels = labels.length == 1 ? [] : labels[0..-2]
        end
        [labels, absolute]
      end

      def make_name(labels, absolute)
        Name.new(labels.map {|s| Label::Str.new(s.b) }, absolute)
      end

      # Completes a raw name token against +origin+.  +@+ denotes the origin;
      # an absolute (trailing dot) name is used unchanged.
      def resolve_name_text(text, origin)
        if text == "@"
          unless origin
            raise ArgumentError, "no current origin for @ name"
          end
          return origin
        end
        labels, absolute = split_domain(text)
        return root_origin if absolute && labels.empty?
        if absolute
          make_name(labels, true)
        elsif origin
          Name.new(labels.map {|s| Label::Str.new(s.b) } + origin.to_a,
                   origin.absolute?)
        else
          make_name(labels, false)
        end
      end

      # Decodes a single character-string token (RFC 1035).  Quotes were only
      # lexical boundaries, so they are not part of the value.
      def unescape_char_string(token)
        unescape_text(token.text)
      end

      def unescape_text(text)
        out = String.new
        i = 0
        while i < text.length
          ch = text[i]
          if ch == BACKSLASH
            if i + 1 >= text.length
              raise ArgumentError, "trailing backslash"
            end
            i += 1
            value, extra = read_escape(text, i)
            out << value
            i += 1 + extra
          else
            out << ch
            i += 1
          end
        end
        out
      end

      # ---- numbers ---------------------------------------------------------

      def parse_uint(token, max, what)
        value = Integer(token.text, 10)
        unless (0..max) === value
          raise ArgumentError, "#{what} out of range (0..#{max}): #{token.text}"
        end
        value
      rescue ArgumentError, TypeError
        raise ArgumentError, "expected an unsigned integer for #{what}, got #{token.text.inspect}"
      end

      def parse_ttl(token)
        text = token.text
        if text =~ /\A\d+\z/
          value = text.to_i
        else
          value = 0
          scanner = text
          until scanner.empty?
            match = /\G(\d+)([WDHMSwdhms])?/.match(scanner)
            unless match
              raise ArgumentError, "invalid TTL: #{text.inspect}"
            end
            number = match[1].to_i
            unit = (match[2] || "S").upcase
            value += number * TTL_UNITS.fetch(unit)
            scanner = scanner[match[0].length..]
          end
        end
        unless (0..0xffffffff) === value
          raise ArgumentError, "TTL out of range: #{text.inspect}"
        end
        value
      end

      # ---- records ---------------------------------------------------------

      def rr_error(file, line, column, message, record_text)
        ParseError.new(message, file: file, line: line, column: column,
                       record: record_text)
      end

      def parse_rr(tokens, origin, default_ttl, last_owner, file,
                   first_line, record_text)
        index = 0
        if tokens.first.at_line_start
          owner = resolve_name_text(tokens.first.text, origin)
          index += 1
        else
          if last_owner.nil?
            raise rr_error(file, first_line, tokens.first.column,
                           "record without owner but no previous owner",
                           record_text)
          end
          owner = last_owner
        end

        ttl = default_ttl
        klass = CLASS_NAMES["IN"]
        ttl_seen = false
        klass_seen = false

        2.times do
          break if index >= tokens.length
          token = tokens[index]
          up = token.text.upcase
          if !ttl_seen && ttl_token?(token)
            ttl = parse_ttl(token)
            ttl_seen = true
            index += 1
          elsif !klass_seen && class_token?(up)
            klass = class_value(up)
            klass_seen = true
            index += 1
          else
            break
          end
        end

        if index >= tokens.length
          raise rr_error(file, first_line, tokens.last.column,
                         "record is missing its type and RDATA", record_text)
        end

        type_token = tokens[index]
        index += 1
        type_name = type_token.text.upcase
        type_value = type_value_of(type_name)

        if ttl.nil?
          raise rr_error(file, first_line, type_token.column,
                         "no TTL for record and no $TTL in effect", record_text)
        end

        resource = build_resource(klass, type_value, type_name,
                                  tokens[index..], origin)
        resource.instance_variable_set(:@ttl, ttl)
        [owner, ttl, resource]
      rescue ParseError
        raise
      rescue => e
        raise rr_error(file, first_line, tokens.first.column, e.message,
                       record_text)
      end

      def ttl_token?(token)
        token.text =~ /\A\d+\z/ || token.text =~ /\A(?:\d+[WDHMSwdhms])+\z/
      end

      def class_token?(up)
        CLASS_NAMES.key?(up) || up =~ /\ACLASS\d+\z/
      end

      def class_value(up)
        if (m = /\ACLASS(\d+)\z/.match(up))
          value = m[1].to_i
          unless value <= 0xffff
            raise ArgumentError, "class number out of range: #{up}"
          end
          value
        else
          CLASS_NAMES.fetch(up)
        end
      end

      def type_value_of(up)
        if (m = /\ATYPE(\d+)\z/.match(up))
          value = m[1].to_i
          unless value.between?(1, 0xffff)
            raise ArgumentError, "type number out of range: #{up}"
          end
          value
        elsif TYPE_NAMES.key?(up)
          TYPE_NAMES.fetch(up)
        else
          raise ArgumentError,
            "unknown record type #{up.inspect} (use TYPE<number> or the RFC 3597 generic form)"
        end
      end

      # Builds the Resource.  Known IN types map to concrete classes; all
      # other classes and unknown IN types use the RFC 3597 generic form.
      def build_resource(klass, type_value, type_name, tokens, origin)
        marker = tokens.first && tokens.first.text == "#"
        if known_in_type?(type_value)
          if klass != CLASS_NAMES["IN"]
            unless marker
              raise ArgumentError,
                "#{type_name} records are only supported in class IN; " \
                "use the RFC 3597 generic form for CLASS#{klass}"
            end
          end
          if marker && klass == CLASS_NAMES["IN"]
            raise ArgumentError,
              "#{type_name} has a structured presentation format; " \
              "the RFC 3597 generic form is only for unknown types"
          end
          build_in_resource(type_value, type_name, tokens, origin)
        else
          build_generic_resource(klass, type_value, tokens, marker)
        end
      end

      def known_in_type?(type_value)
        [
          Resource::IN::A::TypeValue,
          Resource::NS::TypeValue,
          Resource::SOA::TypeValue,
          Resource::CNAME::TypeValue,
          Resource::PTR::TypeValue,
          Resource::HINFO::TypeValue,
          Resource::MINFO::TypeValue,
          Resource::MX::TypeValue,
          Resource::TXT::TypeValue,
          Resource::LOC::TypeValue,
          Resource::CAA::TypeValue,
          Resource::IN::AAAA::TypeValue,
          Resource::IN::SRV::TypeValue,
          Resource::IN::WKS::TypeValue,
          Resource::IN::SVCB::TypeValue,
          Resource::IN::HTTPS::TypeValue,
        ].include?(type_value)
      end

      def require_tokens!(tokens, count, type_name)
        if tokens.length < count
          raise ArgumentError,
            "#{type_name} record needs #{count} RDATA field(s), got #{tokens.length}"
        end
      end

      def domain_token(token, origin)
        resolve_name_text(token.text, origin)
      end

      def char_string(token)
        value = unescape_char_string(token)
        if value.bytesize > 255
          raise ArgumentError, "character-string too long (#{value.bytesize} bytes)"
        end
        value
      end

      def build_in_resource(type_value, type_name, tokens, origin)
        case type_value
        when Resource::IN::A::TypeValue
          require_tokens!(tokens, 1, type_name)
          Resource::IN::A.new(tokens.first.text)
        when Resource::IN::AAAA::TypeValue
          require_tokens!(tokens, 1, type_name)
          Resource::IN::AAAA.new(tokens.first.text)
        when Resource::NS::TypeValue
          require_tokens!(tokens, 1, type_name)
          Resource::IN::NS.new(domain_token(tokens.first, origin))
        when Resource::CNAME::TypeValue
          require_tokens!(tokens, 1, type_name)
          Resource::IN::CNAME.new(domain_token(tokens.first, origin))
        when Resource::PTR::TypeValue
          require_tokens!(tokens, 1, type_name)
          Resource::IN::PTR.new(domain_token(tokens.first, origin))
        when Resource::SOA::TypeValue
          build_soa(tokens, origin)
        when Resource::MX::TypeValue
          require_tokens!(tokens, 2, type_name)
          preference = parse_uint(tokens[0], 0xffff, "MX preference")
          exchange = domain_token(tokens[1], origin)
          Resource::IN::MX.new(preference, exchange)
        when Resource::TXT::TypeValue
          require_tokens!(tokens, 1, type_name)
          Resource::IN::TXT.new(*tokens.map {|t| char_string(t) })
        when Resource::HINFO::TypeValue
          require_tokens!(tokens, 2, type_name)
          Resource::IN::HINFO.new(char_string(tokens[0]), char_string(tokens[1]))
        when Resource::MINFO::TypeValue
          require_tokens!(tokens, 2, type_name)
          Resource::IN::MINFO.new(domain_token(tokens[0], origin),
                                  domain_token(tokens[1], origin))
        when Resource::IN::SRV::TypeValue
          build_srv(tokens, origin)
        when Resource::IN::WKS::TypeValue
          build_wks(tokens)
        when Resource::LOC::TypeValue
          build_loc(tokens)
        when Resource::CAA::TypeValue
          build_caa(tokens)
        when Resource::IN::SVCB::TypeValue, Resource::IN::HTTPS::TypeValue
          build_service_binding(type_value, tokens, origin)
        end
      end

      def build_soa(tokens, origin)
        require_tokens!(tokens, 7, "SOA")
        mname = domain_token(tokens[0], origin)
        rname = domain_token(tokens[1], origin)
        serial = parse_uint(tokens[2], 0xffffffff, "SOA serial")
        timings = tokens[3..6].map {|token| parse_ttl(token) }
        Resource::IN::SOA.new(mname, rname, serial, *timings)
      end

      def build_srv(tokens, origin)
        require_tokens!(tokens, 4, "SRV")
        priority = parse_uint(tokens[0], 0xffff, "SRV priority")
        weight = parse_uint(tokens[1], 0xffff, "SRV weight")
        port = parse_uint(tokens[2], 0xffff, "SRV port")
        target = domain_token(tokens[3], origin)
        Resource::IN::SRV.new(priority, weight, port, target)
      end

      # WKS: address protocol ports...  Port numbers set bits in the bitmap.
      # A leading "0x" token is taken as a raw bitmap instead.
      def build_wks(tokens)
        require_tokens!(tokens, 3, "WKS")
        address = IPv4.create(tokens[0].text)
        protocol = parse_uint(tokens[1], 0xff, "WKS protocol")
        if tokens[2].text =~ /\A0[xX]/
          bitmap = parse_hex(tokens[2].text[2..], "WKS bitmap")
          tokens[3..].each do |token|
            bitmap << parse_hex(token.text.sub(/\A0[xX]/, ""), "WKS bitmap")
          end
        else
          ports = tokens[2..].map {|t| parse_uint(t, 0xffff, "WKS service port") }
          max_port = ports.max || -1
          bitmap = ("\0".b * ((max_port / 8) + 1))
          ports.each do |port|
            byte = port / 8
            bitmap.setbyte(byte, bitmap.getbyte(byte) | (0x80 >> (port % 8)))
          end
        end
        Resource::IN::WKS.new(address, protocol, bitmap)
      end

      # LOC (RFC 1876): d1 [m1 [s1]] NS d2 [m2 [s2]] EW alt [size [hp [vp]]]
      def build_loc(tokens)
        unless (9..12) === tokens.length
          raise ArgumentError, "LOC record needs 9 to 12 fields, got #{tokens.length}"
        end
        lat_text, used1 = loc_coordinate(tokens, %w[N S])
        rest = tokens[(used1 + 1)..]
        lon_text, used2 = loc_coordinate(rest, %w[E W])
        rest = rest[(used2 + 1)..]
        altitude = Resolv::LOC::Alt.create(rest[0].text)
        size = rest[1] ? Resolv::LOC::Size.create(rest[1].text) :
          Resolv::LOC::Size.create("1m")
        hp = rest[2] ? Resolv::LOC::Size.create(rest[2].text) :
          Resolv::LOC::Size.create("10000m")
        vp = rest[3] ? Resolv::LOC::Size.create(rest[3].text) :
          Resolv::LOC::Size.create("10m")
        Resource::LOC.new("\0".b, size, hp, vp,
                          Resolv::LOC::Coord.create(lat_text),
                          Resolv::LOC::Coord.create(lon_text), altitude)
      end

      def loc_coordinate(tokens, directions)
        dir_index = tokens.index do |token|
          directions.include?(token.text.upcase)
        end
        unless dir_index && dir_index.between?(0, 3)
          raise ArgumentError, "LOC coordinate is missing its direction"
        end
        [tokens[0..dir_index].map(&:text).join(" "), dir_index]
      end

      def build_caa(tokens)
        require_tokens!(tokens, 3, "CAA")
        flags_text = tokens[0].text
        flags =
          if flags_text =~ /\A\d+\z/
            flags_text.to_i
          elsif flags_text =~ /\A0x[0-9A-Fa-f]+\z/
            flags_text[2..].to_i(16)
          else
            raise ArgumentError, "invalid CAA flags: #{flags_text.inspect}"
          end
        Resource::CAA.new(flags, tokens[1].text, char_string(tokens[2]).b)
      end

      # SVCB/HTTPS (RFC 9460): priority target [key=value ...]
      def build_service_binding(type_value, tokens, origin)
        type_name = type_value == Resource::IN::SVCB::TypeValue ? "SVCB" : "HTTPS"
        require_tokens!(tokens, 2, type_name)
        priority = parse_uint(tokens[0], 0xffff, "SVCB priority")
        target = domain_token(tokens[1], origin)
        params = tokens[2..].map {|token| build_svc_param(token) }
        klass = type_value == Resource::IN::SVCB::TypeValue ?
          Resource::IN::SVCB : Resource::IN::HTTPS
        klass.new(priority, target, params)
      end

      def build_svc_param(token)
        key_text, _, value_text = token.text.partition("=")
        key = key_text.downcase
        case key
        when "mandatory"
          keys = value_text.split(",").map {|k| svc_key_number(k.strip) }
          SvcParam::Mandatory.new(keys)
        when "alpn"
          SvcParam::ALPN.new(split_alpn(value_text))
        when "no-default-alpn"
          SvcParam::NoDefaultALPN.new
        when "port"
          SvcParam::Port.new(uint_in(value_text, 0xffff, "port"))
        when "ipv4hint"
          addresses = value_text.split(",").map {|a| IPv4.create(strip_quotes(a.strip)) }
          SvcParam::IPv4Hint.new(addresses)
        when "ipv6hint"
          addresses = value_text.split(",").map {|a| IPv6.create(strip_quotes(a.strip)) }
          SvcParam::IPv6Hint.new(addresses)
        when "dohpath"
          SvcParam::DoHPath.new(value_text)
        else
          number = svc_key_number(key)
          SvcParam::Generic.create(number).new(unescape_text(value_text).b)
        end
      end

      def split_alpn(text)
        text.split(",").map do |part|
          strip_quotes(part.strip)
        end
      end

      def svc_key_number(text)
        if (m = /\Akey(\d+)\z/.match(text))
          value = m[1].to_i
          unless value.between?(0, 0xffff)
            raise ArgumentError, "SvcParam key out of range: #{text}"
          end
          value
        elsif text =~ /\A[a-z0-9-]+\z/
          begin
            klass = SvcParam::ClassHash[text.to_sym]
          rescue KeyError
            raise ArgumentError, "unknown SvcParam key #{text.inspect}"
          end
          if klass.respond_to?(:key_number)
            klass.key_number
          else
            raise ArgumentError, "unknown SvcParam key #{text.inspect}"
          end
        else
          raise ArgumentError, "unknown SvcParam key #{text.inspect}"
        end
      end

      def uint_in(text, max, what)
        value = Integer(text, 10)
        unless (0..max) === value
          raise ArgumentError, "#{what} out of range: #{text}"
        end
        value
      rescue ArgumentError, TypeError
        raise ArgumentError, "invalid #{what}: #{text.inspect}"
      end

      def strip_quotes(text)
        if text.length >= 2 && text.start_with?('"') && text.end_with?('"')
          text[1..-2]
        else
          text
        end
      end

      # Parses an RFC 3597 "# rdlength hex..." generic record.
      def build_generic_resource(klass, type_value, tokens, marker)
        unless marker
          raise ArgumentError,
            "TYPE#{type_value}/CLASS#{klass} is only supported in the RFC 3597 " \
            "generic form: # rdlength hex..."
        end
        if tokens.length < 2
          raise ArgumentError, "generic record needs '# rdlength hex...'"
        end
        rdlength = uint_in(tokens[1].text, 0xffff, "rdlength")
        data = parse_hex(tokens[2..].map(&:text).join, "generic RDATA")
        if data.bytesize != rdlength
          raise ArgumentError,
            "generic RDATA length #{data.bytesize} does not match rdlength #{rdlength}"
        end
        Resource::Generic.create(type_value, klass).new(data)
      end

      def parse_hex(hex, what)
        unless hex =~ /\A(?:[0-9A-Fa-f]{2})*\z/
          raise ArgumentError, "#{what} is not a sequence of hex pairs"
        end
        [hex].pack("H*").b
      end

    end
  end
end
