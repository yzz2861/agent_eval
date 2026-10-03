# :markup: markdown
require 'monitor'

module HTTP
  autoload :Cookie, "http/cookie"
end

##
# This class is used to manage the Cookies that have been returned from
# any particular website.

class HTTP::CookieJar

  attr_reader :store

  # The result of re-adjudicating the jar's contents against a suffix
  # rule provider, returned by #replace_suffix_rules and available
  # afterwards via #last_recheck_report.
  class RecheckReport
    # A single adjudication decision made during a recheck.
    class Entry
      # The cookie that was examined.
      attr_reader :cookie

      # What was decided: +:keep+ or +:remove+.
      attr_reader :action

      # Why the decision was made.  One of:
      #
      # [:+:host_only+]
      #   The cookie is host-only; suffix rules do not apply to it,
      #   so it is always kept.
      # [:+:domain_allowed+]
      #   The cookie is a domain cookie whose domain is not a public
      #   suffix under the current rules, so it is kept.
      # [:+:public_suffix+]
      #   The cookie is a domain cookie whose domain is a public
      #   suffix under the current rules, so it is removed.
      # [:+:provider_error+]
      #   The rule provider raised an error; the cookie is removed
      #   because a provider failure must not silently allow a
      #   public suffix (fail closed).
      attr_reader :reason

      # The exception raised by the rule provider, if any.
      attr_reader :error

      def initialize(cookie, action, reason, error = nil)
        @cookie, @action, @reason, @error = cookie, action, reason, error
      end

      def keep?
        @action == :keep
      end

      def remove?
        @action == :remove
      end
    end

    # The suffix rules version (see HTTP::CookieJar#suffix_rules_version)
    # that this recheck ran against.
    attr_reader :version

    # All adjudication entries, one per cookie examined.
    attr_reader :entries

    def initialize(version, entries)
      @version, @entries = version, entries
    end

    # Entries for cookies that were kept.
    def kept
      @entries.select(&:keep?)
    end

    # Entries for cookies that were removed.
    def removed
      @entries.select(&:remove?)
    end

    # Returns the reason symbol recorded for +cookie+, or nil if the
    # cookie was not part of this recheck.
    def reason_for(cookie)
      (entry = @entries.find { |e| e.cookie.equal?(cookie) }) && entry.reason
    end
  end

  def get_impl(base, value, *args)
    case value
    when base
      value
    when Symbol
      begin
        base.implementation(value).new(*args)
      rescue IndexError => e
        raise ArgumentError, e.message
      end
    when Class
      if base >= value
        value.new(*args)
      else
        raise TypeError, 'not a subclass of %s: %s' % [base, value]
      end
    else
      raise TypeError, 'invalid object: %s' % value.inspect
    end
  end
  private :get_impl

  # Generates a new cookie jar.
  #
  # Available option keywords are as below:
  #
  # :store
  # : The store class that backs this jar. (default: `:hash`)
  # A symbol addressing a store class, a store class, or an instance
  # of a store class is accepted.  Symbols are mapped to store
  # classes, like `:hash` to HTTP::CookieJar::HashStore and `:mozilla`
  # to HTTP::CookieJar::MozillaStore.
  #
  # Any options given are passed through to the initializer of the
  # specified store class.  For example, the `:mozilla`
  # (HTTP::CookieJar::MozillaStore) store class requires a `:filename`
  # option.  See individual store classes for details.
  #
  # :suffix_rules
  # : A public-suffix rule provider used to adjudicate domain cookies.
  # Any object responding to #public_suffix?(hostname) is accepted;
  # see HTTP::Cookie::SuffixRules.  (default:
  # HTTP::Cookie::SuffixRules.default)
  #
  # The provider can later be swapped with #replace_suffix_rules,
  # which also re-adjudicates the cookies already in the jar.
  def initialize(options = nil)
    opthash = {
      :store => :hash,
    }
    opthash.update(options) if options
    @store = get_impl(AbstractStore, opthash[:store], opthash)
    @suffix_rules = opthash[:suffix_rules] || HTTP::Cookie::SuffixRules.default
    @suffix_rules_version = 0
    @last_recheck_report = nil
    @suffix_monitor = Monitor.new
  end

  # The copy constructor.  Not all backend store classes support cloning.
  def initialize_copy(other)
    @store = other.instance_eval { @store.dup }
    @suffix_monitor = Monitor.new
  end

  # The suffix rule provider currently in effect.
  def suffix_rules
    @suffix_monitor.synchronize { @suffix_rules }
  end

  # The version of the suffix rules currently in effect, incremented
  # each time #replace_suffix_rules installs a new provider.  Reads
  # such as #each and #cookies are synchronized with rule
  # replacement, so they always observe a single, consistent rule
  # version rather than a mix of old and new rules.
  def suffix_rules_version
    @suffix_monitor.synchronize { @suffix_rules_version }
  end

  # The report of the most recent recheck performed by
  # #replace_suffix_rules, or nil if the rules have never been
  # replaced.
  def last_recheck_report
    @suffix_monitor.synchronize { @last_recheck_report }
  end

  # Replaces the suffix rule provider and re-adjudicates every cookie
  # already in the jar against the new rules, returning a
  # RecheckReport that records, for each cookie, whether it was kept
  # or removed and why.
  #
  # Host-only cookies are not affected by suffix rules and are always
  # kept.  A domain cookie is removed when its domain is a public
  # suffix under the new rules.  If the provider raises an error the
  # jar fails closed: the affected domain cookie is removed with
  # reason :provider_error rather than being allowed to stand.
  #
  # The swap and the recheck are performed atomically with respect to
  # other jar operations, so concurrent readers see either the old
  # rules with the old contents or the new rules with the rechecked
  # contents, never a mixture.
  def replace_suffix_rules(rules)
    rules.respond_to?(:public_suffix?) or
      raise ArgumentError, "suffix rules must respond to #public_suffix?: %s" % rules.inspect
    @suffix_monitor.synchronize {
      @suffix_rules = rules
      @suffix_rules_version += 1
      @last_recheck_report = recheck_cookies
    }
  end

  # Adds a cookie to the jar if it is acceptable, and returns self in
  # any case.  A given cookie must have domain and path attributes
  # set, or ArgumentError is raised.
  #
  # Whether a cookie with the `for_domain` flag on overwrites another
  # with the flag off or vice versa depends on the store used.  See
  # individual store classes for that matter.
  #
  # ### Compatibility Note for Mechanize::Cookie users
  #
  # In HTTP::Cookie, each cookie object can store its origin URI
  # (cf. #origin).  While the origin URI of a cookie can be set
  # manually by #origin=, one is typically given in its generation.
  # To be more specific, HTTP::Cookie.new takes an `:origin` option
  # and HTTP::Cookie.parse takes one via the second argument.
  #
  #       # Mechanize::Cookie
  #       jar.add(origin, cookie)
  #       jar.add!(cookie)    # no acceptance check is performed
  #
  #       # HTTP::Cookie
  #       jar.origin = origin
  #       jar.add(cookie)     # acceptance check is performed
  def add(cookie)
    @suffix_monitor.synchronize {
      @store.add(cookie) if acceptable_to_jar?(cookie)
    }
    self
  end
  alias << add

  # Deletes a cookie that has the same name, domain and path as a
  # given cookie from the jar and returns self.
  #
  # How the `for_domain` flag value affects the set of deleted cookies
  # depends on the store used.  See individual store classes for that
  # matter.
  def delete(cookie)
    @store.delete(cookie)
    self
  end

  # Gets an array of cookies sorted by the path and creation time.  If
  # `url` is given, only ones that should be sent to the URL/URI are
  # selected, with the access time of each of them updated.
  def cookies(url = nil)
    each(url).sort
  end

  # Tests if the jar is empty.  If `url` is given, tests if there is
  # no cookie for the URL.
  def empty?(url = nil)
    if url
      each(url) { return false }
      return true
    else
      @store.empty?
    end
  end

  # Iterates over all cookies that are not expired in no particular
  # order.
  #
  # An optional argument `uri` specifies a URI/URL indicating the
  # destination of the cookies being selected.  Every cookie yielded
  # should be good to send to the given URI,
  # i.e. cookie.valid_for_uri?(uri) evaluates to true.
  #
  # If (and only if) the `uri` option is given, last access time of
  # each cookie is updated to the current time.
  def each(uri = nil, &block) # :yield: cookie
    block_given? or return enum_for(__method__, uri)

    if uri
      uri = HTTP::Cookie::URIParser.parse(uri)
      return self unless URI::HTTP === uri && uri.host
    end

    @suffix_monitor.synchronize {
      @store.each(uri, &block)
    }
    self
  end
  include Enumerable

  # Parses a Set-Cookie field value `set_cookie` assuming that it is
  # sent from a source URL/URI `origin`, and adds the cookies parsed
  # as valid and considered acceptable to the jar.  Returns an array
  # of cookies that have been added.
  #
  # If a block is given, it is called for each cookie and the cookie
  # is added only if the block returns a true value.
  #
  # `jar.parse(set_cookie, origin)` is a shorthand for this:
  #
  #         HTTP::Cookie.parse(set_cookie, origin) { |cookie|
  #           jar.add(cookie)
  #         }
  #
  # See HTTP::Cookie.parse for available options.
  def parse(set_cookie, origin, options = nil) # :yield: cookie
    if block_given?
      HTTP::Cookie.parse(set_cookie, origin, options).tap { |cookies|
        cookies.select! { |cookie|
          yield(cookie) && add(cookie)
        }
      }
    else
      HTTP::Cookie.parse(set_cookie, origin, options) { |cookie|
        add(cookie)
      }
    end
  end

  # call-seq:
  #   jar.save(filename_or_io, **options)
  #   jar.save(filename_or_io, format = :yaml, **options)
  #
  # Saves the cookie jar into a file or an IO in the format specified
  # and returns self.  If a given object responds to #write it is
  # taken as an IO, or taken as a filename otherwise.
  #
  # Available option keywords are below:
  #
  # * `:format`
  #
  #     Specifies the format for saving.  A saver class, a symbol
  #     addressing a saver class, or a pre-generated instance of a
  #     saver class is accepted.
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>:yaml</dt>
  #       <dd>YAML structure (default)</dd>
  #       <dt>:cookiestxt</dt>
  #       <dd>Mozilla's cookies.txt format</dd>
  #     </dl>
  #
  # * `:session`
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>true</dt>
  #       <dd>Save session cookies as well.</dd>
  #       <dt>false</dt>
  #       <dd>Do not save session cookies. (default)</dd>
  #     </dl>
  #
  # All options given are passed through to the underlying cookie
  # saver module's constructor.
  def save(writable, *options)
    opthash = {
      :format => :yaml,
      :session => false,
    }
    case options.size
    when 0
    when 1
      case options = options.first
      when Symbol
        opthash[:format] = options
      else
        if hash = Hash.try_convert(options)
          opthash.update(hash)
        end
      end
    when 2
      opthash[:format], options = options
      if hash = Hash.try_convert(options)
        opthash.update(hash)
      end
    else
      raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
    end

    saver = get_impl(AbstractSaver, opthash[:format], opthash)

    if writable.respond_to?(:write)
      saver.save(writable, self)
    else
      File.open(writable, 'w') { |io|
        saver.save(io, self)
      }
    end

    self
  end

  # call-seq:
  #   jar.load(filename_or_io, **options)
  #   jar.load(filename_or_io, format = :yaml, **options)
  #
  # Loads cookies recorded in a file or an IO in the format specified
  # into the jar and returns self.  If a given object responds to
  # \#read it is taken as an IO, or taken as a filename otherwise.
  #
  # Available option keywords are below:
  #
  # * `:format`
  #
  #     Specifies the format for loading.  A saver class, a symbol
  #     addressing a saver class, or a pre-generated instance of a
  #     saver class is accepted.
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>:yaml</dt>
  #       <dd>YAML structure (default)</dd>
  #       <dt>:cookiestxt</dt>
  #       <dd>Mozilla's cookies.txt format</dd>
  #     </dl>
  #
  # All options given are passed through to the underlying cookie
  # saver module's constructor.
  def load(readable, *options)
    opthash = {
      :format => :yaml,
      :session => false,
    }
    case options.size
    when 0
    when 1
      case options = options.first
      when Symbol
        opthash[:format] = options
      else
        if hash = Hash.try_convert(options)
          opthash.update(hash)
        end
      end
    when 2
      opthash[:format], options = options
      if hash = Hash.try_convert(options)
        opthash.update(hash)
      end
    else
      raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
    end

    saver = get_impl(AbstractSaver, opthash[:format], opthash)

    if readable.respond_to?(:write)
      saver.load(readable, self)
    else
      File.open(readable, 'r') { |io|
        saver.load(io, self)
      }
    end

    self
  end

  # Clears the cookie jar and returns self.
  def clear
    @store.clear
    self
  end

  # Removes expired cookies and returns self.  If `session` is true,
  # all session cookies are removed as well.
  def cleanup(session = false)
    @store.cleanup session
    self
  end

  private

  # Tests if a cookie may enter the jar under the current suffix
  # rules.  Must be called with @suffix_monitor held.
  def acceptable_to_jar?(cookie)
    begin
      cookie.acceptable?
    rescue RuntimeError => e
      raise ArgumentError, e.message
    end or return false
    # Host-only cookies are not affected by suffix rules.  A domain
    # cookie must not target a public suffix; a rule provider failure
    # fails closed and rejects the cookie.
    !cookie.for_domain? || !public_suffix?(cookie.domain)
  end

  # Re-adjudicates every cookie in the jar against the current suffix
  # rules and returns a RecheckReport.  Must be called with
  # @suffix_monitor held.
  def recheck_cookies
    entries = []
    removals = []
    @store.each { |cookie|
      if !cookie.for_domain?
        entries << RecheckReport::Entry.new(cookie, :keep, :host_only)
        next
      end
      begin
        if @suffix_rules.public_suffix?(cookie.domain)
          entries << RecheckReport::Entry.new(cookie, :remove, :public_suffix)
          removals << cookie
        else
          entries << RecheckReport::Entry.new(cookie, :keep, :domain_allowed)
        end
      rescue StandardError => e
        # Fail closed: a provider error must not silently allow a
        # public suffix.
        entries << RecheckReport::Entry.new(cookie, :remove, :provider_error, e)
        removals << cookie
      end
    }
    removals.each { |cookie| @store.delete(cookie) }
    RecheckReport.new(@suffix_rules_version, entries)
  end

  # Asks the current suffix rule provider, failing closed on any
  # provider error.  Must be called with @suffix_monitor held.
  def public_suffix?(host)
    @suffix_rules.public_suffix?(host)
  rescue StandardError
    true
  end
end

require 'http/cookie/suffix_rules'
require 'http/cookie_jar/abstract_store'
require 'http/cookie_jar/abstract_saver'
