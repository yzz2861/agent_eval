# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The early_hints plugin allows sending 103 Early Hints responses
    # using the rack.early_hints environment variable.
    # Early hints allow clients to preload necessary files before receiving
    # the response.
    #
    # In addition to the low level send_early_hints method, which sends
    # immediately, the plugin can buffer Link early hints for the duration
    # of the request, so multiple routing branches (and plugins such as
    # +assets+) can contribute hints without sending duplicate resources:
    #
    #   route do |r|
    #     early_hint '/assets/app.css', :as => 'style'
    #     early_hint '/assets/app.js', :as => 'script'
    #
    #     r.on 'admin' do
    #       # This hint is not needed if the branch redirects:
    #       early_hint '/assets/admin.js', :as => 'script'
    #       remove_early_hints '/assets/admin.js'
    #       r.redirect('/login') unless logged_in?
    #
    #       commit_early_hints
    #       view('admin')
    #     end
    #
    #     commit_early_hints
    #     view
    #   end
    #
    # Hints are deduplicated by both target URI and attributes, so hints
    # for the same target with different attributes (such as +as+ or
    # +crossorigin+) are both kept, while exactly matching hints are only
    # sent once.
    #
    # Buffered hints are only sent when commit_early_hints is called, so
    # branches that redirect do not send the hints they collected. After a
    # commit the buffer is empty; hints collected afterwards are held in a
    # new buffer and require another explicit commit to be sent.
    #
    # If the +rack.early_hints+ callback is not present in the environment,
    # collecting, deduplicating, and withdrawing hints still works, but
    # committing and sending are no-ops and the response is returned
    # normally.
    module EarlyHints
      module InstanceMethods
        # Send given hash of Early Hints using the rack.early_hints
        # environment variable, currently only supported by puma.  hash
        # given should generally have the single key 'Link', and a string
        # or array of strings for each of the early hints.
        #
        # Unlike the other methods in this plugin, this sends the hints
        # immediately, without buffering or deduplication.  If there is no
        # rack.early_hints callback in the environment, this is a no-op.
        def send_early_hints(hash)
          if eh_proc = env['rack.early_hints']
            eh_proc.call(hash)
          end
        end

        # Add a Link early hint to the buffer for the current request,
        # without sending it yet.  All buffered hints are sent together
        # when commit_early_hints is called.
        #
        # The target can be a path or URI, with or without angle brackets,
        # with attributes given as keyword arguments:
        #
        #   early_hint('/assets/app.css', :as => 'style')
        #   # </assets/app.css>; rel=preload; as=style
        #
        # A complete Link value (as accepted by send_early_hints) can be
        # given directly:
        #
        #   early_hint('</assets/app.js>; rel=preload; as=script')
        #
        # Multiple hints can be passed as an array, or as a hash with a
        # single Link key whose value is a string or array of strings:
        #
        #   early_hint(['</a.css>; rel=preload; as=style',
        #               '</b.js>; rel=preload; as=script'])
        #   early_hint(RodaResponseHeaders::LINK => '</a.css>; rel=preload; as=style')
        #
        # Hints are deduplicated by target and attributes: hints for the
        # same target with different attributes are all kept, but adding
        # an identical hint more than once has no effect.  Returns nil.
        def early_hint(hint, attrs=OPTS)
          _early_hint_entries(hint, attrs).each do |target, key, value|
            unless _early_hints_buffer.any?{|buffered_target, buffered_key, _| buffered_target == target && buffered_key == key}
              _early_hints_buffer << [target, key, value]
            end
          end
          nil
        end

        # Withdraw buffered Link early hints for the given resource target,
        # so they are not sent by a later commit_early_hints.  Hints that
        # have already been committed cannot be withdrawn.
        #
        # The target can be given with or without angle brackets.  With no
        # attributes, all buffered hints for the target are withdrawn:
        #
        #   remove_early_hints('/assets/app.js')
        #
        # With attributes, only hints for the target containing all of the
        # given attributes are withdrawn, so other hints for the same
        # target are kept:
        #
        #   remove_early_hints('/assets/font.woff2', :crossorigin => true)
        #
        # Returns the withdrawn Link values, or an empty array if nothing
        # buffered matched.
        def remove_early_hints(target, attrs=OPTS)
          target = _early_hints_target(target)
          attributes = _early_hints_attributes(attrs)

          kept, withdrawn = _early_hints_buffer.partition do |hint_target, hint_key,|
            next true unless hint_target == target
            if attributes.empty?
              next false
            end
            !attributes.all?{|pair| hint_key.any?{|name, value| name == pair[0] && value == pair[1]}}
          end
          @_early_hints = kept
          withdrawn.map(&:last)
        end

        # Send all buffered Link early hints in a single early hints
        # response, then empty the buffer.  Hints collected after the
        # commit go into a fresh buffer and are not sent until
        # commit_early_hints is called again.
        #
        # Returns the hash passed to the rack.early_hints callback, or nil
        # if the buffer was empty or there is no rack.early_hints callback.
        def commit_early_hints
          return if _early_hints_buffer.empty?

          values = _early_hints_buffer.map(&:last).freeze
          @_early_hints = []

          link = if defined?(Rack.release) && Rack.release >= '3'
            values
          else
            values.join("\n".freeze)
          end

          hash = {RodaResponseHeaders::LINK => link}
          if env['rack.early_hints']
            send_early_hints(hash)
            hash
          end
        end

        private

        # Per-request buffer of collected Link early hints, as
        # [target, dedup_key, link_value] arrays, kept in insertion order.
        def _early_hints_buffer
          @_early_hints ||= []
        end

        # Convert the accepted early_hint inputs into [target, key, value]
        # buffer entries.
        def _early_hint_entries(hint, attrs=OPTS)
          if hint.is_a?(Hash)
            unless hint.length == 1
              raise RodaError, "early_hint only supports buffered Link hints, use send_early_hints for other early hints"
            end
            header, value = hint.first
            unless header.to_s.downcase == RodaResponseHeaders::LINK
              raise RodaError, "early_hint only supports buffered Link hints, use send_early_hints for other early hints"
            end
            return _early_hint_entries(value)
          end

          Array(hint).flat_map do |entry|
            if attrs.empty? && entry.is_a?(String) && entry.start_with?('<'.freeze)
              target, parameters = _early_hints_parse_link(entry)
              [[target, parameters.sort, entry]]
            else
              [_early_hint_built_entry(entry, attrs)]
            end
          end
        end

        # Build a buffer entry from a target and attribute hash.
        def _early_hint_built_entry(target, attrs)
          attributes = _early_hints_attributes(attrs)
          unless attributes.any?{|name, _| name == 'rel'}
            attributes = [['rel', 'preload'.freeze]] + attributes
          end

          target = _early_hints_target(target)
          [target, attributes.sort, _early_hints_format_link(target, attributes)]
        end

        # Normalize an attribute hash into [name, value] string pairs,
        # dropping attributes with false values and representing bare
        # attributes (true values) with a nil value.
        def _early_hints_attributes(attrs)
          attributes = []
          attrs.each do |name, value|
            next if value == false
            attributes << [name.to_s, value == true ? nil : value.to_s]
          end
          attributes
        end

        # Extract the target URI, with or without surrounding angle
        # brackets.
        def _early_hints_target(target)
          target = target.to_s
          if target.start_with?('<') && target.end_with?('>')
            target[1...-1]
          else
            target
          end
        end

        # Format a target URI and normalized attribute pairs as a Link
        # value.
        def _early_hints_format_link(target, attributes)
          value = "<#{target}>".dup
          attributes.each do |name, attribute_value|
            value << "; ".freeze << name
            unless attribute_value.nil?
              if attribute_value =~ /[\s;"]/
                value << '="' << attribute_value.gsub('"', '\\"') << '"'
              else
                value << '=' << attribute_value
              end
            end
          end
          value
        end

        # Parse a single Link value into a target URI and an array of
        # [name, value] parameters, respecting quoted parameter values and
        # treating bare parameters (such as crossorigin) as nil values.
        def _early_hints_parse_link(link_value)
          unless link_value =~ /\A\s*<([^>]*)>(.*)\z/m
            raise RodaError, "invalid Link early hint: #{link_value.inspect}"
          end
          target = $1
          parameters = []

          $2.scan(/;\s*([^=;"\s]+)(?:=(?:"((?:[^"\\]|\\.)*)"|([^;\s]*)))?/m) do |name, quoted, unquoted|
            if quoted
              parameters << [name, quoted]
            elsif unquoted.nil? || unquoted.empty?
              parameters << [name, nil]
            else
              parameters << [name, unquoted]
            end
          end

          [target, parameters]
        end
      end
    end

    register_plugin(:early_hints, EarlyHints)
  end
end
