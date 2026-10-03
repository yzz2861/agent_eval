# frozen_string_literal: true

module I18n
  # An explicit marker that a translation key has been intentionally
  # disabled for a locale. Unlike a +nil+ translation (which keeps the old
  # "missing" semantics and therefore keeps falling back to other locales,
  # other backends and defaults) a disabled key terminates the lookup right
  # away:
  #
  # * locale fallbacks are not consulted,
  # * further backends in a I18n::Backend::Chain are not consulted,
  # * +:default+ translations are not used,
  # * the marker is never returned (nor leaked) from a translate call.
  #
  # In Ruby translation data it can be used directly:
  #
  #   I18n.backend.store_translations(:de, :promo => I18n::DISABLED)
  #
  # The equivalent declaration in YAML/JSON files is the string
  # +"I18N_DISABLED"+:
  #
  #   de:
  #     promo: I18N_DISABLED
  class DisabledTranslation < MissingTranslation
    def message
      "Translation disabled: #{keys.join('.')}"
    end
    alias :to_s :message

    # A DisabledTranslation is never a plain MissingTranslation.
    def disabled?
      true
    end

    def to_exception
      DisabledTranslationData.new(locale, key, options)
    end
  end

  # Raised by I18n.t! (the :raise/:throw path) for a disabled key. Keeping a
  # distinct class lets callers distinguish "intentionally off" from a plain
  # missing translation while still being rescued as MissingTranslationData.
  class DisabledTranslationData < MissingTranslationData
    def message
      "Translation disabled: #{keys.join('.')}"
    end
    alias :to_s :message

    def disabled?
      true
    end
  end

  # The single marker object stored in translation data to express that a
  # key is explicitly disabled. It is a DisabledTranslation instance so it
  # can travel through the same code paths as a thrown exception and is
  # instantly recognizable by +#disabled?+.
  DISABLED = DisabledTranslation.new(nil, nil, {}).freeze

  # The textual token accepted in YAML/JSON translation files.
  DISABLED_TOKEN = 'I18N_DISABLED'
end
