# frozen_string_literal: true

require_relative 'generic'

module URI

  # RFC 8141 Uniform Resource Name.
  class URN < Generic
    COMPONENT = [
      :scheme,
      :nid,
      :nss,
      :r_component,
      :q_component,
      :fragment,
    ].freeze

    NID = %r{\A[0-9A-Za-z][0-9A-Za-z-]{0,30}[0-9A-Za-z]\z}
    private_constant :NID

    PCHAR = /(?:%\h\h|[!$&-;=@A-Z_a-z~])/.freeze
    private_constant :PCHAR

    NSS = %r{\A#{PCHAR}*\z}
    private_constant :NSS

    R_COMPONENT = %r{\A(?:(?!\?=)(?:#{PCHAR}|[/?]))*\z}
    private_constant :R_COMPONENT

    Q_COMPONENT = %r{\A(?:(?!\?\+)(?:#{PCHAR}|[/?]))*\z}
    private_constant :Q_COMPONENT

    FRAGMENT_COMPONENT = %r{\A(?:#{PCHAR}|[/?])*\z}
    private_constant :FRAGMENT_COMPONENT

    NAMING = %r{
      \A(?<nid>[^:]+):(?<nss>#{PCHAR}*)
      (?:\?\+(?<r_component>(?:(?!\?=)(?:#{PCHAR}|[/?]))*))?
      (?:\?=(?<q_component>(?:(?!\?\+)(?:#{PCHAR}|[/?]))*))?
      \z
    }x.freeze
    private_constant :NAMING

    def self.build(args)
      components = Util.make_components_hash(self, args)
      components[:r_component] = components.delete(:r) if components.key?(:r)
      components[:q_component] = components.delete(:q) if components.key?(:q)
      validate_build_components(components)
      new(components[:scheme],
          nil, nil, nil, nil,
          nil, build_namestring(components),
          nil,
          components[:fragment],
          DEFAULT_PARSER,
      true)
    end

    def self.validate_build_components(components)
      require_component_string(:nid, components[:nid], NID)
      require_component_string(:nss, components[:nss], NSS)
      validate_optional_component(:r_component, components[:r_component], R_COMPONENT)
      validate_optional_component(:q_component, components[:q_component], Q_COMPONENT)
      validate_optional_component(:fragment, components[:fragment], FRAGMENT_COMPONENT)
    end
    private_class_method :validate_build_components

    def self.require_component_string(name, value, pattern)
      string = String.try_convert(value)
      unless string && pattern.match?(string)
        raise InvalidComponentError, "bad component(expected #{name} component): #{value}"
      end
    end
    private_class_method :require_component_string

    def self.validate_optional_component(name, value, pattern)
      require_component_string(name, value, pattern) unless value.nil?
    end
    private_class_method :validate_optional_component

    def self.build2(args)
      escaped_args =
        case args
        when Array
          args.each_with_index.map { |value, index| escape_build_component(index, value) }
        when Hash
          escaped_args = {}
          args.each { |name, value| escaped_args[name] = escape_build_component(name, value) }
          escaped_args
        else
          args
        end
      build(escaped_args)
    end

    def self.escape_build_component(name, value)
      return value unless value.is_a?(String)

      case name
      when 0, :nid
        value
      when 1, :nss
        RFC2396_PARSER.escape(value, /[^%!$&'()*+,-.:;=@0-9A-Z_a-z~]/)
      when 2, :r, :r_component
        escape_r_component(value)
      when 3, :q, :q_component
        escape_q_component(value)
      else
        RFC2396_PARSER.escape(value, %r{[^%!$&'()*+,-.:;=@0-9A-Z_a-z~/?]})
      end
    end
    private_class_method :escape_build_component

    def self.escape_r_component(value)
      RFC2396_PARSER.escape(value, %r{[^%!$&'()*+,-.:;=@0-9A-Z_a-z~/?]}).gsub(/\?(?==)/, '%3F')
    end
    private_class_method :escape_r_component

    def self.escape_q_component(value)
      RFC2396_PARSER.escape(value, %r{[^%!$&'()*+,-.:;=@0-9A-Z_a-z~/?]}).gsub(/\?(?=\+)/, '%3F')
    end
    private_class_method :escape_q_component

    def self.build_namestring(components)
      namestring = +"#{components[:nid]}:#{components[:nss]}"
      unless components[:r_component].nil?
        namestring << "?+"
        namestring << components[:r_component]
      end
      unless components[:q_component].nil?
        namestring << "?="
        namestring << components[:q_component]
      end
      namestring
    end
    private_class_method :build_namestring

    def initialize(*arguments)
      super(*arguments)

      check_scheme(@scheme)
      parse_namestring(@opaque.to_s)

      if arguments[10]
        self.nid = @nid
        self.nss = @nss
        self.r_component = @r_component
        self.q_component = @q_component
        self.fragment = @fragment
      else
        set_nid(@nid)
        set_nss(@nss)
        set_r_component(@r_component)
        set_q_component(@q_component)
      end
    end

    attr_reader :nid
    attr_reader :nss
    attr_reader :r_component
    attr_reader :q_component
    alias r r_component
    alias q q_component

    def check_scheme(v)
      unless v&.downcase == 'urn'
        raise InvalidComponentError, "bad component(expected urn scheme): #{v}"
      end
      true
    end
    private :check_scheme

    def check_nid(v)
      value = String.try_convert(v)
      unless value && NID.match?(value) &&
             value.casecmp('urn') != 0 && !value.downcase.start_with?('urn-')
        raise InvalidComponentError, "bad component(expected namespace identifier): #{v}"
      end
      true
    end
    private :check_nid

    def check_nss(v)
      check_component(:nss, v, NSS)
    end
    private :check_nss

    def check_r_component(v)
      check_component(:r_component, v, R_COMPONENT)
    end
    private :check_r_component

    def check_q_component(v)
      check_component(:q_component, v, Q_COMPONENT)
    end
    private :check_q_component

    def check_fragment(v)
      check_component(:fragment, v, FRAGMENT_COMPONENT)
    end
    private :check_fragment

    def check_component(name, v, pattern)
      return true if v.nil?
      value = String.try_convert(v)
      unless value && pattern.match?(value)
        raise InvalidComponentError, "bad component(expected #{name} component): #{v}"
      end
      true
    end
    private :check_component

    def set_nid(v)
      @nid = v
      build_namestring!
      v
    end
    protected :set_nid

    def set_nss(v)
      @nss = v
      build_namestring!
      v
    end
    protected :set_nss

    def set_r_component(v)
      @r_component = v
      build_namestring!
      v
    end
    protected :set_r_component

    def set_q_component(v)
      @q_component = v
      build_namestring!
      v
    end
    protected :set_q_component

    def nid=(v)
      check_nid(v)
      set_nid(v)
      v
    end

    def nss=(v)
      check_nss(v)
      set_nss(v)
    end

    def r_component=(v)
      check_r_component(v)
      set_r_component(v)
    end
    alias r= r_component=

    def q_component=(v)
      check_q_component(v)
      set_q_component(v)
    end
    alias q= q_component=

    def fragment=(v)
      check_fragment(v)
      @fragment = v
    end

    def opaque=(v)
      parse_namestring(v.to_str)
      set_nid(@nid)
      set_nss(@nss)
      set_r_component(@r_component)
      set_q_component(@q_component)
      v
    end

    def hierarchical?
      false
    end

    def normalize!
      set_nid(@nid.downcase) if @nid
      set_nss(@nss.gsub(/%\h\h/) { |pct_encoded| pct_encoded.upcase })
      self
    end

    def ==(other)
      return false unless self.class == other.class
      normalized_nid == other.normalized_nid &&
        normalized_nss == other.normalized_nss
    end

    def eql?(other)
      self.class == other.class && component_ary.eql?(other.component_ary)
    end

    def hash
      [normalized_nid, normalized_nss].hash
    end

    def to_s
      str = +"#{@scheme}:#{@opaque}"
      str << "##{@fragment}" if @fragment
      str
    end

    def select(*components)
      components = components.map do |component|
        case component
        when :r then :r_component
        when :q then :q_component
        else component
        end
      end
      super(*components)
    end

    protected

    def normalized_nid
      @nid.downcase
    end

    def normalized_nss
      @nss.gsub(/%\h\h/) { |pct| pct.upcase }
    end

    def parse_namestring(value)
      string = String.try_convert(value)
      match = string && NAMING.match(string)
      unless match
        raise InvalidComponentError, "bad URN namespace-specific string: #{value}"
      end

      nid = match[:nid]
      check_nid(nid)
      nss = match[:nss]
      check_nss(nss)
      r_component = match[:r_component]
      check_r_component(r_component)
      q_component = match[:q_component]
      check_q_component(q_component)

      @nid = nid
      @nss = nss
      @r_component = r_component
      @q_component = q_component
      @opaque = string
    end

    def build_namestring!
      namestring = +"#{@nid}:#{@nss}"
      namestring << "?+#{@r_component}" unless @r_component.nil?
      namestring << "?=#{@q_component}" unless @q_component.nil?
      @opaque = namestring
    end
  end

  register_scheme 'URN', URN
end
