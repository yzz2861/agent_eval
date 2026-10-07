# -*- ruby encoding: utf-8 -*-
require_relative 'error'

class Net::LDAP
  class Sync
    REFRESH_ONLY = 1
    REFRESH_AND_PERSIST = 3

    MODES = {
      :refreshOnly => REFRESH_ONLY,
      :refresh_only => REFRESH_ONLY,
      'refreshOnly' => REFRESH_ONLY,
      REFRESH_ONLY => REFRESH_ONLY,
      :refreshAndPersist => REFRESH_AND_PERSIST,
      :refresh_and_persist => REFRESH_AND_PERSIST,
      'refreshAndPersist' => REFRESH_AND_PERSIST,
      REFRESH_AND_PERSIST => REFRESH_AND_PERSIST,
    }.freeze

    Event = Struct.new(:type,
                       :uuid,
                       :entry,
                       :cookie,
                       :refresh_deletes,
                       :refresh_done,
                       :reload_hint,
                       :uuids,
                       keyword_init: true)

    class ProtocolError < Net::LDAP::Error; end

    def initialize(connection)
      @connection = connection
    end

    def run(args, &block)
      raise ArgumentError, "a block is required" unless block

      @block = block
      @refresh_path = nil
      @refresh_confirmed = false
      @refresh_started = false
      @refresh_initial_seen = false
      @refresh_announced = false
      @refresh_done_emitted = false
      @phase_one_entries = []
      @pending_deletes = []

      mode = mode_for(args.fetch(:mode, :refreshOnly))
      message_id = @connection.next_msgid

      write_search(args, mode, message_id)
      read_messages(args, mode, message_id)
    ensure
      @connection.message_queue.delete(message_id) if message_id
    end

    private

    def mode_for(mode)
      MODES.fetch(mode) do
        raise ArgumentError, "invalid synchronization mode: #{mode.inspect}"
      end
    end

    def write_search(args, mode, message_id)
      filter = args[:filter] || Net::LDAP::Filter.eq("objectClass", "*")
      filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
      base = args[:base]
      scope = args[:scope] || Net::LDAP::SearchScope_WholeSubtree
      deref = args[:deref] || Net::LDAP::DerefAliases_Never
      attributes = Array(args[:attributes]).map { |attribute| attribute.to_s.to_ber }
      size = args[:size].to_i
      time = args[:time].to_i
      attributes_only = args[:attributes_only] == true

      raise ArgumentError, "search base is required" unless base
      raise ArgumentError, "invalid search scope" unless Net::LDAP::SearchScopes.include?(scope)
      raise ArgumentError, "invalid alias dereferencing value" unless Net::LDAP::DerefAliasesArray.include?(deref)

      request = [
        base.to_ber,
        scope.to_ber_enumerated,
        deref.to_ber_enumerated,
        size.to_ber,
        time.to_ber,
        attributes_only.to_ber,
        filter.to_ber,
        attributes.to_ber_sequence,
      ].to_ber_appsequence(Net::LDAP::PDU::SearchRequest)

      controls = Array(args[:controls]) + [sync_control(mode, args)]
      @connection.send(:write, request, controls.to_ber_contextspecific(0), message_id)
    end

    def sync_control(mode, args)
      cookie = args[:cookie]
      reload_hint = args[:reload_hint] == true
      criticality = args.fetch(:critical, true)
      value = [mode.to_ber_enumerated]

      if cookie && !cookie.to_s.empty?
        value << cookie.to_s.dup.force_encoding(Encoding::BINARY).to_ber_bin(0x80)
      end
      value << ber_boolean(reload_hint, 0x81) if reload_hint

      [
        Net::LDAP::LDAPControls::SYNC_REQUEST.to_ber,
        criticality.to_ber,
        value.join.to_ber,
      ].to_ber_sequence
    end

    def read_messages(args, mode, message_id)
      result_pdu = nil

      while (pdu = @connection.queued_read(message_id))
        case pdu.app_tag
        when Net::LDAP::PDU::SearchReturnedData
          handle_entry(pdu, mode)
        when Net::LDAP::PDU::IntermediateResponse
          handle_intermediate(pdu, mode)
        when Net::LDAP::PDU::SearchResultReferral
          next
        when Net::LDAP::PDU::SearchResult
          result_pdu = pdu
          handle_result(pdu, mode)
          break
        else
          raise ProtocolError, "unexpected synchronization response: #{pdu.app_tag}"
        end

        break if !result_pdu.nil? && mode == REFRESH_ONLY
      end

      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing" if result_pdu.nil?
      result_pdu
    end

    def handle_entry(pdu, mode)
      control = control(pdu, Net::LDAP::LDAPControls::SYNC_STATE)
      raise ProtocolError, "search entry is missing syncState control" unless control

      state, uuid, cookie = parse_sequence(control.value)
      if state == 0
        if mode == REFRESH_ONLY || @refresh_done_emitted || @refresh_path.nil?
          emit_current_entry(pdu, state, uuid, cookie)
        else
          @phase_one_entries << Event.new(type: :present,
                                          uuid: uuid,
                                          entry: pdu.search_entry,
                                          cookie: cookie)
        end
      elsif @refresh_confirmed || @refresh_initial_seen || @refresh_path.nil?
        emit_current_entry(pdu, state, uuid, cookie)
      end
    end

    def emit_current_entry(pdu, state, uuid, cookie)
      type = case state
             when 0 then :present
             when 1 then :add
             when 2 then :modify
             when 3 then :delete
             else raise ProtocolError, "invalid syncState: #{state.inspect}"
             end

      emit(type: type,
           uuid: uuid,
           entry: pdu.search_entry,
           cookie: cookie)
    end

    def handle_intermediate(pdu, mode)
      response = pdu.intermediate_response
      return unless response && response[:name] == Net::LDAP::LDAPControls::SYNC_INFO

      raw_choice = response[:value]
      choice = raw_choice
      tag = choice.ber_identifier & 0x1f
      choice = choice.is_a?(Array) ? choice : parse_sequence(choice)
      choice = choice.first if choice.length == 1 && choice.first.is_a?(Array)

      case tag
      when 0
        emit(type: :new_cookie, cookie: choice)
      when 1, 2
        handle_refresh(choice, tag, mode)
      when 3
        handle_sync_id_set(choice)
      else
        raise ProtocolError, "invalid syncInfo choice: #{tag}"
      end
    end

    def handle_refresh(choice, tag, mode)
      cookie = tagged_value(choice, 0)
      refresh_done = tagged_value(choice, 1, false)
      @refresh_path = tag == 1 ? :refresh_delete : :refresh_present

      if refresh_done
        if !@refresh_announced && !@refresh_started
          emit_refresh_start(cookie)
        end
        unless @refresh_done_emitted
          flush_pending_deletes
          @phase_one_entries.each { |event| @block.call(event) }
          @phase_one_entries.clear
          emit(type: :refresh_done,
               cookie: cookie,
               refresh_deletes: tag == 1)
          @refresh_done_emitted = true
        end
        @refresh_confirmed = true
      else
        @refresh_confirmed = false
        @refresh_done_emitted = false
        @refresh_initial_seen = mode == REFRESH_ONLY
        @refresh_announced = true
        @refresh_started = true
      end
    end

    def handle_sync_id_set(choice)
      cookie = tagged_value(choice, 0)
      refresh_deletes = tagged_value(choice, 1, false)
      uuid_set = choice.detect do |element|
        element.respond_to?(:ber_identifier) && (element.ber_identifier & 0x1f) == 2
      end
      uuids = uuid_set.is_a?(Array) ? uuid_set : parse_sequence(uuid_set)
      if refresh_deletes
        @refresh_path = :refresh_delete
        emit_refresh_start(cookie)
        @pending_deletes.concat(uuids)
      else
        uuids.each { |uuid| emit(type: :present, uuid: uuid) }
      end
    end

    def handle_result(pdu, mode)
      if pdu.result_code == Net::LDAP::ResultCodeSyncRefreshRequired
        emit(type: :refresh_required, reload_hint: true)
        return
      end

      return unless pdu.result_code == Net::LDAP::ResultCodeSuccess

      control = control(pdu, Net::LDAP::LDAPControls::SYNC_DONE)
      raise ProtocolError, "search result is missing syncDone control" unless control

      cookie, refresh_deletes = parse_sequence(control.value)
      @refresh_path = refresh_deletes ? :refresh_delete : :refresh_present

      unless @refresh_confirmed
        emit_refresh_start(cookie)
        flush_pending_deletes
        emit(type: :refresh_done,
             cookie: cookie,
             refresh_deletes: refresh_deletes)
        @refresh_confirmed = true
      end

      emit(type: :sync_done,
           cookie: cookie,
           refresh_deletes: refresh_deletes)
    end

    def control(pdu, oid)
      pdu.result_controls.detect { |candidate| candidate.oid == oid }
    end

    def parse_sequence(value)
      io = StringIO.new(value)
      result = []
      while element = io.read_ber(BER_SYNTAX)
        result << element
      end
      result
    end

    def tagged_value(sequence, tag, default = nil)
      index = sequence.index do |candidate|
        if candidate.is_a?(TrueClass) || candidate.is_a?(FalseClass)
          tag == 1
        else
          candidate.respond_to?(:ber_identifier) && (candidate.ber_identifier & 0x1f) == tag
        end
      end
      index.nil? ? default : sequence[index]
    end

    def emit(attributes)
      @block.call(Event.new(attributes))
    end

    def emit_refresh_start(cookie)
      return if @refresh_started

      emit(type: (@refresh_path == :refresh_delete ? :refresh_delete : :refresh_present),
           cookie: cookie,
           refresh_done: false)
      @refresh_started = true
    end

    def flush_pending_deletes
      @pending_deletes.each { |uuid| emit(type: :delete, uuid: uuid) }
      @pending_deletes.clear
    end

    def ber_boolean(value, tag)
      [tag, 1, value ? 0xFF : 0x00].pack("CCC")
    end

    BER_SYNTAX = Net::BER.compile_syntax(
      universal: {
        primitive: {
          1 => :boolean,
          2 => :integer,
          4 => :string,
          10 => :integer,
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
        },
        constructed: {
          0 => :array,
          1 => :array,
          2 => :array,
          3 => :array,
        },
      },
    )
  end
end
