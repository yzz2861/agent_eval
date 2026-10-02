# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The early_hints plugin allows sending 103 Early Hints responses
    # using the rack.early_hints environment variable.
    # Early hints allow clients to preload necessary files before receiving
    # the response.
    #
    # In addition to being able to send early hints immediately, this plugin
    # allows collecting Link hints during routing (possibly from multiple
    # plugins and routing branches), withdrawing hints for resources that
    # will not be used (for example, because the request is later
    # redirected), and then explicitly submitting all collected hints once.
    #
    # == Immediate sending
    #
    # To send early hints immediately, use send_early_hints:
    #
    #   send_early_hints('Link' => '</foo.js>; rel=preload; as=script')
    #
    # send_early_hints does not affect the collected hints, so it can be
    # freely combined with the collecting API described below.
    #
    # == Collecting hints
    #
    # add_early_hint collects a Link hint for a resource, but does not send
    # it until commit_early_hints is called:
    #
    #   add_early_hint('/foo.js', :as => 'script')
    #   # Equivalent to collecting: </foo.js>; rel=preload; as=script
    #
    # The resource can be given as a path or a full URL (without the
    # surrounding angle brackets).  The rel attribute defaults to
    # +preload+, and any other link attributes can be given (such as
    # +as+ and +crossorigin+):
    #
    #   add_early_hint('/font.woff2', :as => 'font', :crossorigin => nil)
    #
    # A raw Link header value (or array of values) can also be collected
    # directly:
    #
    #   add_early_hint('</foo.js>; rel=preload; as=script')
    #   add_early_hint(['</a.css>; rel=preload; as=style', '</b.js>; rel=preload; as=script'])
    #
    # Hints are deduplicated by the resource and all of their attributes.
    # A single resource may therefore have multiple distinct hints, for
    # example the same file used with different +as+ values, but collecting
    # the exact same resource/attribute combination more than once still
    # results in a single hint:
    #
    #   add_early_hint('/a.js', :as => 'script')
    #   add_early_hint('/a.js', :as => 'script') # ignored, already collected
    #   add_early_hint('/a.js', :as => 'fetch', :crossorigin => nil) # separate hint
    #
    # Attribute order does not matter when deduplicating.
    #
    # == Withdrawing hints
    #
    # remove_early_hint withdraws previously collected hints for a resource.
    # Without attributes, it removes all collected hints for the resource,
    # regardless of their attributes:
    #
    #   remove_early_hint('/foo.js')
    #
    # With attributes, it only removes the hint matching the given
    # attributes:
    #
    #   remove_early_hint('/a.js', :as => 'script')
    #
    # Removing a resource or attribute combination that has not been
    # collected has no effect.
    #
    # == Submitting collected hints
    #
    # commit_early_hints submits all collected hints using the
    # rack.early_hints environment variable, then clears the collected hints:
    #
    #   commit_early_hints
    #
    # Because commit_early_hints clears the collected hints, hints can be
    # collected and submitted multiple times within the same request, each
    # submission sending only the hints collected (and not removed) since the
    # previous submission.  This allows hinting for additional resources
    # after an initial submission:
    #
    #   add_early_hint('/a.css', :as => 'style')
    #   commit_early_hints # sends hint for /a.css
    #   add_early_hint('/b.js', :as => 'script')
    #   commit_early_hints # sends hint for /b.js only
    #
    # If the rack.early_hints environment variable is not set (for example,
    # when the web server does not support early hints), send_early_hints and
    # commit_early_hints do nothing, and the page is returned normally.
    # Collected hints are still tracked, deduplicated, and cleared on commit
    # in that case.
    module EarlyHints
      module InstanceMethods
        # Send given hash of Early Hints using the rack.early_hints environment variable,
        # currenly only supported by puma.  hash given should generally have the single
        # key 'Link', and a string or array of strings for each of the early hints.
        def send_early_hints(hash)
          if eh_proc = env['rack.early_hints']
            eh_proc.call(hash)
          end
        end

        # Collect a Link hint for the resource given by +uri+, to be sent
        # when commit_early_hints is called.  See the EarlyHints module
        # documentation for accepted forms and deduplication behavior.
        def add_early_hint(uri, attrs=OPTS)
          links = _early_hint_links(uri, attrs)
          collected = (@early_hints ||= {})
          links.each do |target, link_attrs|
            collected[[target, _early_hint_canonical_attrs(link_attrs)]] ||= [target, link_attrs]
          end
          nil
        end

        # Withdraw a previously collected Link hint.  With no attrs, remove
        # all collected hints for the resource given by +uri+.  With attrs,
        # only remove the hint matching the resource and attributes.
        def remove_early_hint(uri, attrs=nil)
          return unless @early_hints

          if attrs
            @early_hints.delete([_early_hint_target(uri), _early_hint_canonical_attrs(_early_hint_attrs(attrs))])
          else
            target = _early_hint_target(uri)
            @early_hints.delete_if{|(link_target, _), _| link_target == target }
          end
          nil
        end

        # Send all collected Link hints using the rack.early_hints
        # environment variable, then clear the collected hints.  Does
        # nothing if no hints have been collected (and not removed) since
        # the previous commit, or if rack.early_hints is not supported by
        # the web server.
        def commit_early_hints
          return unless @early_hints && !@early_hints.empty?

          links = @early_hints.values.map{|target, attrs| _early_hint_line(target, attrs)}
          @early_hints.clear

          if eh_proc = env['rack.early_hints']
            links = links.join("\n") if Rack.release < '3'
            eh_proc.call(RodaResponseHeaders::LINK => links)
          end
          nil
        end

        private

        # Return an array of target/attributes pairs collected from the
        # given arguments.
        def _early_hint_links(uri, attrs)
          if attrs.empty? && uri.is_a?(String) && uri.start_with?('<')
            return _early_hint_parse(uri)
          elsif attrs.empty? && uri.is_a?(Array)
            return uri.flat_map{|link| _early_hint_parse(link)}
          end

          [[_early_hint_target(uri), _early_hint_attrs(attrs)]]
        end

        # Parse one or more raw Link header values into target/attributes
        # pairs.
        def _early_hint_parse(link)
          link.split(/,\s*(?=<)/).map do |entry|
            target, params = entry.split(';', 2)
            target = target.strip
            target = target[1...-1] if target.start_with?('<') && target.end_with?('>')

            link_attrs = {}
            if params
              params.split(';').each do |param|
                key, value = param.strip.split('=', 2)
                if value
                  value = value[1...-1] if value.start_with?('"') && value.end_with?('"')
                end
                link_attrs[key.freeze] = value
              end
            end
            link_attrs['rel'] ||= 'preload'

            [target, link_attrs]
          end
        end

        # Return the target URI without surrounding angle brackets.
        def _early_hint_target(uri)
          uri = uri.to_s
          if uri.start_with?('<') && uri.end_with?('>')
            uri[1...-1]
          else
            uri
          end
        end

        # Normalize given link attributes, defaulting rel to preload.
        def _early_hint_attrs(attrs)
          link_attrs = {'rel' => 'preload'}
          attrs.each do |key, value|
            link_attrs[key.to_s] = value
          end
          link_attrs
        end

        # Return an immutable representation of the attributes used for
        # deduplication, ignoring parameter order.
        def _early_hint_canonical_attrs(attrs)
          attrs.each_key.map(&:to_s).sort.map do |key|
            value = attrs[key]
            [key.freeze, value.nil? ? nil : value.to_s.freeze].freeze
          end.freeze
        end

        # Serialize a target/attributes pair as a single Link value.
        def _early_hint_line(target, attrs)
          params = _early_hint_canonical_attrs(attrs).partition{|key, _| key == 'rel'}
          rel = params[0].empty? ? [['rel', 'preload'.freeze]] : params[0]
          params = rel + params[1]
          "<#{target}>; " + params.map do |key, value|
            value.nil? ? key : "#{key}=#{value.match?(/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/) ? value : "\"#{value}\""}"
          end.join('; ')
        end
      end
    end

    register_plugin(:early_hints, EarlyHints)
  end
end
