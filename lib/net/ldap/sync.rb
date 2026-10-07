# -*- ruby encoding: utf-8 -*-
require 'ostruct'

class Net::LDAP
  module Sync
    OID = '1.3.6.1.4.1.4203.1.9.1.1'.freeze
    STATE_OID = '1.3.6.1.4.1.4203.1.9.1.2'.freeze
    INFO_OID = '1.3.6.1.4.1.4203.1.9.1.3'.freeze
    DONE_OID = '1.3.6.1.4.1.4203.1.9.1.4'.freeze

    REFRESH_ONLY = 1
    REFRESH_AND_PERSIST = 3

    STATE_PRESENT = 0
    STATE_ADD = 1
    STATE_MODIFY = 2
    STATE_DELETE = 3

    SyncSyntax = Net::BER.compile_syntax(
      universal: {
        primitive: {
          1 => :boolean,
          2 => :integer,
          4 => :string,
          6 => :oid,
          10 => :integer,
          13 => :oid,
        },
        constructed: {
          16 => :array,
          17 => :array,
        },
      },
      context_specific: {
        primitive: {
          0 => :string,
          1 => :boolean,
          2 => :boolean,
          7 => :string,
        },
        constructed: {
          0 => :array,
          1 => :array,
          2 => :array,
          3 => :array,
        },
      },
    )

    def self.oid(value)
      return value if value.is_a?(::String)

      if value.first == 1 && value[1] == 9
        [1, 3, value[2..-1]].flatten.join('.')
      else
        value.join('.')
      end
    end

    def self.control(controls, oid)
      return unless controls

      controls.find { |control| Sync.oid(control.oid) == oid }
    end

    def self.oid_ber(oid)
      Net::BER::BerIdentifiedOid.new(oid).to_ber
    end

    def self.control_value(control)
      return unless control && control.value

      value = normalize_ber(control.value)
      value.read_ber(SyncSyntax)
    end

    def self.normalize_ber(value)
      return value unless value.is_a?(::Net::BER::BerIdentifiedArray)

      content = value.map { |item| normalize_item(item) }.join
      [value.ber_identifier].pack('C') + content.length.to_ber_length_encoding + content
    end

    def self.normalize_item(item)
      if item.is_a?(::Net::BER::BerIdentifiedArray)
        normalize_ber(item)
      elsif item.is_a?(::String) && item.ber_identifier != 0x04
        [item.ber_identifier].pack('C') + item.length.to_ber_length_encoding + item
      else
        item.to_ber
      end
    end

    def self.state(pdu)
      value = control_value(control(pdu.ldap_controls, STATE_OID))
      return unless value

      OpenStruct.new(
        state: value[0],
        entry_uuid: value[1],
        cookie: value[2],
      )
    end

    def self.info(pdu)
      value = control_value(control(pdu.ldap_controls, INFO_OID))
      return unless value

      choice = value.ber_identifier & 0x1f
      body = value
      fields = {}
      if body.respond_to?(:each)
        body.each_with_index do |item, index|
          if item.respond_to?(:ber_identifier)
            identifier = item.ber_identifier & 0x1f
          elsif item == true || item == false
            identifier = choice == 2 ? 2 : 1
          else
            identifier = 0
          end
          fields[identifier] = item
        end
      end

      case choice
      when 0
        OpenStruct.new(kind: :newcookie, cookie: body[0])
      when 1
        OpenStruct.new(
          kind: :refresh_delete,
          cookie: fields[0],
          refresh_done: fields.fetch(1, true),
        )
      when 2
        OpenStruct.new(
          kind: :refresh_present,
          cookie: fields[0],
          refresh_done: fields.fetch(2, true),
        )
      when 3
        OpenStruct.new(
          kind: :sync_id_set,
          cookie: fields[0],
          refresh_deletes: fields.fetch(1, false),
          uuids: fields[2] || [],
        )
      end
    end

    def self.done(pdu)
      value = control_value(control(pdu.ldap_controls, DONE_OID))
      return unless value

      first = value[0]
      if first == true || first == false
        OpenStruct.new(refresh_deletes: value[0], cookie: value[1])
      else
        OpenStruct.new(refresh_deletes: false, cookie: value[0])
      end
    end

    def self.request_control(mode, cookie, reload_hint)
      value = [mode.to_ber_enumerated]
      value << cookie.to_ber if cookie
      value << reload_hint.to_ber if reload_hint

      [
        oid_ber(OID),
        true.to_ber,
        value.to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence
    end

    def self.entry_uuid(entry, state)
      (state && state.entry_uuid) || entry[:entryuuid].first
    end

    class ProtocolError < Net::LDAP::Error; end
    class TruncatedError < ProtocolError; end

    class Handler
      def initialize(block, initial_cookie: nil, resumed: false)
        @block = block
        @cookie = initial_cookie
        @phase = nil
        @refresh_deletes = nil
        @complete = resumed
        @acknowledged_cookie = initial_cookie
      end

      attr_reader :cookie, :acknowledged_cookie, :refresh_deletes

      def call(pdu)
        case pdu.app_tag
        when PDU::SearchReturnedData
          entry(pdu)
        when PDU::IntermediateResponse
          intermediate(pdu)
        when PDU::SearchResult
          result(pdu)
        else
          raise ProtocolError, "unexpected PDU type in synchronization response: #{pdu.app_tag}"
        end
      end

      def eof!
        if @complete
          { status: :eof, cookie: cookie, terminal: true }
        else
          raise TruncatedError, "synchronization response ended before refresh was complete"
        end
      end

      private

      def entry(pdu)
        state = Sync.state(pdu)
        unless state
          raise ProtocolError, "search entry is missing the syncState control"
        end

        uuid = Sync.entry_uuid(pdu.search_entry, state)
        unless uuid
          raise ProtocolError, "search entry is missing entryUUID"
        end

        type = case state.state
               when Sync::STATE_PRESENT then :present
               when Sync::STATE_ADD then :add
               when Sync::STATE_MODIFY then :modify
               when Sync::STATE_DELETE then :delete
               else
                 raise ProtocolError, "unknown syncState value: #{state.state}"
               end

        event = {
          type: type,
          entry_uuid: uuid,
          dn: pdu.search_entry.dn,
          cookie: state.cookie,
        }
        event[:entry] = pdu.search_entry unless type == :delete
        emit(event)
        @cookie = state.cookie if state.cookie
        nil
      end

      def intermediate(pdu)
        info = Sync.info(pdu)
        unless info
          raise ProtocolError, "intermediate response is missing the syncInfo control"
        end

        case info.kind
        when :newcookie
          new_cookie(info.cookie)
          nil
        when :refresh_present
          start_refresh(:refresh_present, info.cookie, false, info.refresh_done)
        when :refresh_delete
          start_refresh(:refresh_delete, info.cookie, true, info.refresh_done)
        when :sync_id_set
          emit(
            type: info.refresh_deletes ? :delete_ids : :modify_ids,
            entry_uuids: info.uuids,
            cookie: info.cookie,
          )
          @cookie = info.cookie if info.cookie
          nil
        end
      end

      def start_refresh(phase, cookie, refresh_deletes, refresh_done)
        if @phase
          raise ProtocolError, "received #{phase} during #{@phase}"
        end

        @phase = phase
        @refresh_deletes = refresh_deletes
        emit(
          type: :refresh_start,
          phase: phase,
          refresh_deletes: refresh_deletes,
          cookie: cookie,
        )
        @cookie = cookie if cookie
        complete_refresh if refresh_done == true
        nil
      end

      def new_cookie(cookie)
        if @phase && !@complete
          complete_refresh(cookie)
        else
          emit(type: :cookie, cookie: cookie)
          @cookie = cookie
        end
      end

      def complete_refresh(cookie = nil)
        @complete = true
        emit(
          type: :refresh_complete,
          phase: @phase,
          refresh_deletes: @refresh_deletes,
          cookie: cookie,
        )
        @cookie = cookie if cookie
      end

      def result(pdu)
        if pdu.result_code == ResultCodeSyncRefreshRequired
          done = Sync.done(pdu)
          event = {
            type: :refresh_required,
            refresh_deletes: done && done.refresh_deletes,
            cookie: done && done.cookie,
            result: pdu,
            terminal: true,
          }
          emit(event)
          return { status: :refresh_required, cookie: event[:cookie], result: pdu, terminal: true }
        end

        unless pdu.result_code == ResultCodeSuccess
          raise Net::LDAP::Error, pdu.error_message
        end

        unless @phase
          raise ProtocolError, "search result did not contain a syncInfo refresh marker"
        end

        done = Sync.done(pdu)
        @refresh_deletes = done.refresh_deletes if done && !done.refresh_deletes.nil?
        complete_refresh(done&.cookie)
        { status: :complete, cookie: cookie, result: pdu, terminal: true }
      end

      def emit(event)
        @block.call(event)
        @acknowledged_cookie = event[:cookie] if event.key?(:cookie)
        nil
      end
    end
  end

  ResultCodeSyncRefreshRequired = 16401
end
