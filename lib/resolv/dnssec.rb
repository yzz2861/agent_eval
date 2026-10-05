# frozen_string_literal: true

require 'openssl'
require 'resolv'

class Resolv
  class DNS
    # Offline DNSSEC RRset verification primitives.
    module DNSSEC
      ALGORITHM_RSASHA256 = 8
      CLASS_IN = 1
      TYPE_RRSIG = 46
      TYPE_DNSKEY = 48

      class ValidationError < ArgumentError; end

      Record = Struct.new(:name, :type, :rr_class, :ttl, :rdata)
      RRset = Struct.new(:name, :type, :rr_class, :records)

      RRSIG = Struct.new(
        :type_covered,
        :algorithm,
        :labels,
        :original_ttl,
        :expiration,
        :inception,
        :key_tag,
        :signer,
        :signature,
        :rdata,
        :owner
      ) do
        def self.parse(rdata)
          wire = Resolv::DNS::DNSSEC.binary(rdata)
          raise ValidationError, 'RRSIG RDATA is too short' if wire.bytesize < 18

          fields = wire.unpack('nCCNNNn')
          position = 18
          labels = []
          name_size = 1

          loop do
            if position >= wire.bytesize
              raise ValidationError, 'malformed RRSIG RDATA: truncated signer name'
            end
            length = wire.getbyte(position)
            if length.zero?
              position += 1
              break
            elsif length < 64
              if position + 1 + length > wire.bytesize
                raise ValidationError, 'malformed RRSIG RDATA: truncated signer label'
              end
              begin
                labels << Label::Str.new(wire.byteslice(position + 1, length))
              rescue ArgumentError => error
                raise ValidationError, "malformed RRSIG RDATA: #{error.message}"
              end
              name_size += 1 + length
              if name_size > 255
                raise ValidationError, 'malformed RRSIG RDATA: signer name is too long'
              end
              position += 1 + length
            else
              raise ValidationError, 'malformed RRSIG RDATA: compressed signer name'
            end
          end
          signer = Name.new(labels)
          signature = wire.byteslice(position, wire.bytesize - position)
          new(*fields, signer, signature, wire, nil)
        end
      end

      DNSKEY = Struct.new(
        :flags,
        :protocol,
        :algorithm,
        :public_key,
        :rdata,
        :key_tag
      ) do
        def self.parse(rdata)
          wire = Resolv::DNS::DNSSEC.binary(rdata)
          raise ValidationError, 'DNSKEY RDATA is too short' if wire.bytesize < 4

          flags, protocol, algorithm = wire.unpack('nCC')
          new(flags, protocol, algorithm, wire.byteslice(4, wire.bytesize - 4),
              wire, Resolv::DNS::DNSSEC.key_tag(wire))
        end
      end

      Result = Struct.new(:status, :reason, :signed_data) do
        def valid?
          status == :valid
        end

        def trusted?
          false
        end

        def message
          case status
          when :valid
            'RRset signature matches the supplied DNSKEY; ' +
            'the key itself is not asserted as trusted'
          else
            reason
          end
        end
      end

      class << self
        def verify_rrset(rrset:, rrsig:, dnskey:, time: Time.now)
          rrset = coerce_rrset(rrset)
          rrsig = coerce_rrsig(rrsig)
          dnskey = coerce_dnskey(dnskey)
          now = time.respond_to?(:to_i) ? time.to_i : Integer(time)

          validate_rrsig_shape(rrsig)
          validate_dnskey_shape(dnskey)
          validate_rrset_shape(rrset)
          signed_owner = signed_owner_name(rrset.name, rrsig)

          if rrsig.type_covered != rrset.type
            return failure(:type_mismatch,
                           "RRSIG covers type #{rrsig.type_covered}, " +
                           "but RRset type is #{rrset.type}")
          end

          if rrsig.algorithm != dnskey.algorithm
            return failure(:algorithm_mismatch,
                           "RRSIG algorithm #{rrsig.algorithm} does not match " +
                           "DNSKEY algorithm #{dnskey.algorithm}")
          end

          if rrsig.algorithm != ALGORITHM_RSASHA256
            return failure(:unsupported_algorithm,
                           "algorithm #{rrsig.algorithm} is not supported; " +
                           'only RSASHA256 (8) is supported')
          end

          if dnskey.key_tag != rrsig.key_tag
            return failure(:key_tag_mismatch,
                           "RRSIG key tag #{rrsig.key_tag} does not match " +
                           "DNSKEY key tag #{dnskey.key_tag}")
          end

          if dnskey.protocol != 3
            return failure(:invalid_dnskey, 'DNSKEY protocol field must be 3')
          end

          if now > rrsig.expiration
            return failure(:expired,
                           "signature expired at #{rrsig.expiration}; " +
                           "verification time is #{now}")
          end

          if now < rrsig.inception
            return failure(:not_yet_valid,
                           "signature becomes valid at #{rrsig.inception}; " +
                           "verification time is #{now}")
          end

          signed_data = build_signed_data(rrset, rrsig, signed_owner)
          unless verify_rsa_sha256(dnskey.public_key, rrsig.signature, signed_data)
            return failure(:invalid_signature,
                           'signature does not match the RRset and supplied DNSKEY')
          end

          Result.new(:valid, nil, signed_data)
        end

        def build_signed_data(rrset, rrsig, signed_owner = nil)
          rrset = coerce_rrset(rrset)
          rrsig = coerce_rrsig(rrsig)
          signed_owner ||= signed_owner_name(rrset.name, rrsig)

          data = ''.b
          data << rrsig_prefix(rrsig)
          data << canonical_name(rrsig.signer)
          canonical_rdatas(rrset.records).each do |rdata|
            data << canonical_name(signed_owner)
            fields = [rrset.type, rrset.rr_class, rrsig.original_ttl, rdata.bytesize]
            data << fields.pack('nnNn')
            data << rdata
          end
          data
        end

        def key_tag(dnskey_rdata)
          wire = binary(dnskey_rdata)
          accumulator = 0
          wire.each_byte.with_index do |byte, index|
            accumulator += index.even? ? byte << 8 : byte
          end
          accumulator += (accumulator >> 16) & 0xffff
          accumulator & 0xffff
        end

        def canonical_name(name)
          name = Name.create(name)
          raise ValidationError, 'DNSSEC names must be absolute' unless name.absolute?

          data = ''.b
          name.to_a.each do |label|
            bytes = label.downcase.dup.force_encoding(Encoding::BINARY)
            data << [bytes.bytesize].pack('C')
            data << bytes
          end
          data << "\0".b
          data
        end

        def binary(value)
          raise ValidationError, 'value must be a String' unless value.is_a?(String)
          value.b
        end

        def rrsig_prefix(rrsig)
          [
            rrsig.type_covered,
            rrsig.algorithm,
            rrsig.labels,
            rrsig.original_ttl,
            rrsig.expiration,
            rrsig.inception,
            rrsig.key_tag
          ].pack('nCCNNNn')
        end

        private

        def failure(status, reason)
          Result.new(status, reason, nil)
        end

        def validate_rrsig_shape(rrsig)
          validate_uint(:type_covered, rrsig.type_covered, 0xffff)
          validate_uint(:algorithm, rrsig.algorithm, 0xff)
          validate_uint(:labels, rrsig.labels, 0xff)
          validate_uint(:original_ttl, rrsig.original_ttl, 0xffffffff)
          validate_uint(:expiration, rrsig.expiration, 0xffffffff)
          validate_uint(:inception, rrsig.inception, 0xffffffff)
          validate_uint(:key_tag, rrsig.key_tag, 0xffff)
          unless rrsig.signature.is_a?(String)
            raise ValidationError, 'RRSIG signature must be a String'
          end
          canonical_name(rrsig.signer)
          canonical_name(rrsig.owner) if rrsig.owner
        end

        def validate_dnskey_shape(dnskey)
          validate_uint(:flags, dnskey.flags, 0xffff)
          validate_uint(:protocol, dnskey.protocol, 0xff)
          validate_uint(:algorithm, dnskey.algorithm, 0xff)
          validate_uint(:key_tag, dnskey.key_tag, 0xffff)
          unless dnskey.public_key.is_a?(String)
            raise ValidationError, 'DNSKEY public key must be a String'
          end
          unless dnskey.rdata.nil? || dnskey.rdata.is_a?(String)
            raise ValidationError, 'DNSKEY RDATA must be a String'
          end
        end

        def validate_uint(field, value, maximum)
          unless value.is_a?(Integer) && value >= 0 && value <= maximum
            raise ValidationError, "#{field} must be an unsigned integer no larger than #{maximum}"
          end
        end

        def coerce_rrset(value)
          case value
          when RRset then value
          when Hash
            RRset.new(value[:name], value[:type], value[:rr_class] || value[:class],
                      value[:records])
          else
            raise ValidationError, 'rrset must be an RRset or Hash'
          end
        end

        def coerce_rrsig(value)
          case value
          when RRSIG then value
          when String then RRSIG.parse(value)
          when Hash
            if value.key?(:rdata)
              rrsig = RRSIG.parse(value[:rdata])
              rrsig.owner = value[:owner] if value.key?(:owner)
              rrsig
            else
              parse_or_use(value, RRSIG, :rdata)
            end
          else
            raise ValidationError, 'rrsig must be an RRSIG, Hash, or RDATA String'
          end
        end

        def coerce_dnskey(value)
          case value
          when DNSKEY then value
          when String then DNSKEY.parse(value)
          when Hash then parse_or_use(value, DNSKEY, :rdata)
          else
            raise ValidationError, 'dnskey must be a DNSKEY, Hash, or RDATA String'
          end
        end

        def parse_or_use(hash, struct, rdata_key)
          return struct.parse(hash[rdata_key]) if hash.key?(rdata_key)
          fields = struct.members.map {|member| hash[member] }
          struct.new(*fields)
        end

        def validate_rrset_shape(rrset)
          unless rrset.name && rrset.type && rrset.rr_class && !rrset.records.nil?
            raise ValidationError, 'RRset must include name, type, class, and records'
          end
          raise ValidationError, 'RRset must not be empty' if rrset.records.empty?

          rrset.records.each {|record| validate_record(record, rrset) }
        end

        def validate_record(record, rrset)
          record = coerce_record(record)
          owner_name = Name.create(rrset.name)
          record_name = Name.create(record.name)
          raise ValidationError, 'DNSSEC names must be absolute' unless owner_name.absolute?
          raise ValidationError, 'DNSSEC names must be absolute' unless record_name.absolute?
          unless record_name.to_a == owner_name.to_a
            raise ValidationError, 'all records in an RRset must have the same owner name'
          end
          if record.type != rrset.type || record.rr_class != rrset.rr_class
            raise ValidationError, 'all records in an RRset must have the same type and class'
          end
          unless record.rdata.is_a?(String) || record.rdata.respond_to?(:encode_rdata)
            raise ValidationError, 'record RDATA must be a String or encodable DNS resource'
          end
        end

        def coerce_record(record)
          case record
          when Record then record
          when Hash
            Record.new(record[:name], record[:type], record[:rr_class] || record[:class],
                       record[:ttl], record[:rdata])
          when Array
            name, type, rr_class, ttl, rdata = record
            Record.new(name, type, rr_class, ttl, rdata)
          else
            raise ValidationError, 'records must be Record, Hash, or Array values'
          end
        end

        def signed_owner_name(owner, rrsig)
          owner_name = Name.create(owner)
          raise ValidationError, 'RRset owner name must be absolute' unless owner_name.absolute?

          labels = owner_name.to_a
          validate_labels_count(rrsig, labels.length)
          return owner_name if rrsig.labels == labels.length

          if rrsig.owner
            wildcard_name = Name.create(rrsig.owner)
            unless wildcard_name.absolute? && wildcard_name.length == labels.length &&
                   wildcard_name[0].to_s == '*' &&
                   wildcard_name.to_a[1, labels.length - 1] == labels[1, labels.length - 1]
              raise ValidationError, 'RRSIG owner is not the wildcard owner of this RRset'
            end
            wildcard_name
          else
            Name.new([Label::Str.new('*')] + labels[1, labels.length - 1])
          end
        end

        def validate_labels_count(rrsig, count)
          if rrsig.labels < 0 || rrsig.labels > count || rrsig.labels < count - 1
            raise ValidationError,
                  "RRSIG labels value #{rrsig.labels} does not match #{count}-label owner name"
          end
        end

        def canonical_rdatas(records)
          rdatas = records.map {|record| canonical_rdata(coerce_record(record).rdata) }
          if rdatas.length != rdatas.uniq.length
            raise ValidationError, 'an RRset must not contain duplicate records'
          end
          rdatas.sort
        end

        def canonical_rdata(rdata)
          return rdata.b if rdata.is_a?(String)
          unless rdata.respond_to?(:encode_rdata)
            raise ValidationError, 'record RDATA must be a String or encodable DNS resource'
          end

          encoder = CanonicalEncoder.new
          rdata.encode_rdata(encoder)
          encoder.to_s
        end

        def verify_rsa_sha256(public_key_wire, signature, signed_data)
          raise ValidationError, 'DNSKEY public key is empty' if public_key_wire.empty?
          raise ValidationError, 'RRSIG signature is empty' if signature.empty?
          public_key = rsa_public_key(public_key_wire)
          public_key.verify(OpenSSL::Digest::SHA256.new, signature.b, signed_data)
        rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error, ArgumentError
          false
        end

        def rsa_public_key(wire)
          wire = binary(wire)
          raise ValidationError, 'RSA public key is too short' if wire.bytesize < 2

          position = 0
          exponent_length = wire.getbyte(position)
          position += 1
          if exponent_length.zero?
            raise ValidationError, 'RSA public key is too short' if wire.bytesize < 3
            exponent_length = wire.getbyte(1) << 8 | wire.getbyte(2)
            position = 3
          end

          exponent = minimal_integer(wire.byteslice(position, exponent_length))
          modulus_position = position + exponent_length
          if modulus_position > wire.bytesize
            raise ValidationError, 'RSA exponent length is invalid'
          end
          modulus_bytes = wire.byteslice(modulus_position,
                                         wire.bytesize - modulus_position)
          modulus = minimal_integer(modulus_bytes)
          raise ValidationError, 'RSA exponent is empty' if exponent == "\x00".b
          raise ValidationError, 'RSA modulus is empty' if modulus == "\x00".b

          der = der_sequence(der_integer(modulus) + der_integer(exponent))
          OpenSSL::PKey::RSA.new(der)
        end

        def minimal_integer(bytes)
          bytes = bytes.b.sub(/\A\x00+/, ''.b)
          bytes = "\x00".b if bytes.empty?
          bytes
        end

        def der_integer(bytes)
          bytes = "\x00".b + bytes if bytes.getbyte(0) & 0x80 != 0
          der_tlv(0x02, bytes)
        end

        def der_sequence(content)
          der_tlv(0x30, content)
        end

        def der_tlv(tag, content)
          length = content.bytesize
          length_bytes = if length < 128
                           [length].pack('C')
                         elsif length < 256
                           [0x81, length].pack('CC')
                         else
                           [0x82, length].pack('Cn')
                         end
          ([tag].pack('C') + length_bytes + content).b
        end
      end

      class CanonicalEncoder < Message::MessageEncoder
        def initialize
          @data = ''.dup
          @names = {}
        end

        def put_name(name, compress: false)
          super(name, compress: false)
        end

        def put_label(label)
          bytes = label.downcase.dup.force_encoding(Encoding::BINARY)
          put_string(bytes)
        end
      end
      private_constant(:CanonicalEncoder)
    end
  end
end
