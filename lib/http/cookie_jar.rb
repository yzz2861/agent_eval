# :markup: markdown

module HTTP
  autoload :Cookie, "http/cookie"
end

##
# This class is used to manage the Cookies that have been returned from
# any particular website.

class HTTP::CookieJar

  attr_reader :store

  # The outcome of re-adjudicating the jar's contents after the
  # public suffix rules were replaced (see
  # #replace_public_suffix_list).
  #
  # Every cookie that was examined is recorded with an action
  # (+:kept+ or +:removed+) and a reason:
  #
  # [:+:host_only+]
  #   Kept.  Host-only cookies are bound to an exact host and are
  #   never scoped by suffix rules.
  # [:+:registrable_domain+]
  #   Kept.  The cookie's domain is still a registrable domain under
  #   the current rules.
  # [:+:public_suffix+]
  #   Removed.  The cookie's domain has become a public suffix.
  # [:+:provider_error+]
  #   Removed.  The rule provider failed, and a failure is never
  #   defaulted to allowing a public suffix (fail closed).
  class RecheckReport
    Entry = Struct.new(:cookie, :action, :reason)

    include Enumerable

    # The rules version (HTTP::CookieJar#rules_version) this recheck
    # was performed under.
    attr_accessor :rules_version

    def initialize
      @entries = []
    end

    def record(cookie, action, reason) # :nodoc:
      @entries << Entry.new(cookie, action, reason)
      self
    end

    def each(&block)
      @entries.each(&block)
    end

    # Cookies that survived the recheck.
    def kept
      select { |entry| entry.action == :kept }.map(&:cookie)
    end

    # Cookies that were removed by the recheck.
    def removed
      select { |entry| entry.action == :removed }.map(&:cookie)
    end

    # The reason a given cookie was kept or removed, or nil if the
    # cookie was not part of the recheck.
    def reason_for(cookie)
      if (entry = find { |e| e.cookie.equal?(cookie) })
        entry.reason
      end
    end

    def empty?
      @entries.empty?
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
  # :public_suffix_list
  # : A rule provider used to decide whether the domain of a domain
  # cookie is a public suffix.  Any object responding to
  # `public_suffix?(hostname)` is accepted; see
  # HTTP::Cookie::PublicSuffixList.  Defaults to
  # HTTP::Cookie::PublicSuffixList.default.  The provider can be
  # replaced later with #replace_public_suffix_list, which also
  # re-adjudicates the cookies already in the jar.
  def initialize(options = nil)
    opthash = {
      :store => :hash,
    }
    opthash.update(options) if options
    @rules_lock = Mutex.new
    @public_suffix_list = opthash[:public_suffix_list] || HTTP::Cookie::PublicSuffixList.default
    validate_public_suffix_list!(@public_suffix_list)
    @rules_version = 0
    @last_recheck = nil
    @store = get_impl(AbstractStore, opthash[:store], opthash)
  end

  # The copy constructor.  Not all backend store classes support cloning.
  def initialize_copy(other)
    @rules_lock = Mutex.new
    @store = other.instance_eval { @store.dup }
  end

  # The public suffix rule provider currently in effect.
  attr_reader :public_suffix_list

  # The version of the suffix rules currently in effect.  It starts
  # at 0 and is incremented every time the provider is replaced.
  attr_reader :rules_version

  # The report of the most recent rules recheck, or nil if the
  # provider has never been replaced.
  attr_reader :last_recheck

  # Replaces the public suffix rule provider and re-adjudicates every
  # cookie already in the jar against the new rules, not just future
  # writes.  Domain cookies whose domain is now a public suffix are
  # removed; host-only cookies are left untouched.  Returns a
  # RecheckReport (also available as #last_recheck) from which the
  # fate and reason of each cookie can be queried.
  #
  # The swap and the recheck are performed atomically with respect to
  # other jar operations: reads such as #each and #cookies either see
  # the old rules with the old contents or the new rules with the
  # rechecked contents, never a mixture.
  def replace_public_suffix_list(provider)
    provider ||= HTTP::Cookie::PublicSuffixList.default
    validate_public_suffix_list!(provider)
    report = nil
    @rules_lock.synchronize do
      @public_suffix_list = provider
      @rules_version += 1
      report = recheck_domain_cookies
      report.rules_version = @rules_version
    end
    @last_recheck = report
    report
  end
  alias public_suffix_list= replace_public_suffix_list

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
    @rules_lock.synchronize do
      if acceptable_under_rules?(cookie)
        @store.add(cookie)
      end
    end
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
    @rules_lock.synchronize { @store.delete(cookie) }
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
      @rules_lock.synchronize { @store.empty? }
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

    # Materialize under the rules lock so that a concurrent
    # #replace_public_suffix_list cannot change the rule version in
    # the middle of a read.
    selected = @rules_lock.synchronize {
      cookies = []
      @store.each(uri) { |cookie| cookies << cookie }
      cookies
    }
    selected.each(&block)
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
    @rules_lock.synchronize { @store.clear }
    self
  end

  # Removes expired cookies and returns self.  If `session` is true,
  # all session cookies are removed as well.
  def cleanup(session = false)
    @rules_lock.synchronize { @store.cleanup(session) }
    self
  end

  private

  def validate_public_suffix_list!(provider)
    provider.respond_to?(:public_suffix?) or
      raise ArgumentError, 'public suffix list provider must respond to #public_suffix?'
  end

  def acceptable_under_rules?(cookie)
    acceptable = begin
      cookie.acceptable?
    rescue RuntimeError => e
      raise ArgumentError, e.message
    end
    acceptable && !domain_cookie_on_public_suffix?(cookie)
  end

  # Fail closed: a rule lookup failure is treated as "public suffix"
  # so that a domain cookie is never allowed by default.
  def domain_cookie_on_public_suffix?(cookie)
    return false unless cookie.for_domain?
    domain = cookie.domain
    return false if domain.nil? || domain.empty?
    @public_suffix_list.public_suffix?(domain) ? true : false
  rescue StandardError
    true
  end

  # Must be called with @rules_lock held.
  def recheck_domain_cookies
    report = RecheckReport.new
    removals = []
    @store.each do |cookie|
      if cookie.for_domain?
        if (reason = domain_recheck_reason(cookie.domain))
          report.record(cookie, :removed, reason)
          removals << cookie
        else
          report.record(cookie, :kept, :registrable_domain)
        end
      else
        report.record(cookie, :kept, :host_only)
      end
    end
    removals.each { |cookie| @store.delete(cookie) }
    report
  end

  def domain_recheck_reason(domain)
    @public_suffix_list.public_suffix?(domain) ? :public_suffix : nil
  rescue StandardError
    :provider_error
  end
end

require 'http/cookie_jar/abstract_store'
require 'http/cookie_jar/abstract_saver'
require 'http/cookie/public_suffix_list'
