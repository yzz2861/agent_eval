require 'test_helper'

class I18nBackendVariantsTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Pluralization
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.default_locale = :en
    I18n.backend = Backend.new
    I18n.fallbacks = [:en]
  end

  test "selects a variant and pluralizes the chosen branch (variant then plural)" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => {
        :formal => { :one => 'Dear %{name}, %{count} invitation', :other => 'Dear %{name}, %{count} invitations' },
        :casual => { :one => 'Hi %{name}, %{count} invite', :other => 'Hi %{name}, %{count} invites' },
        :_default => { :one => 'Hello %{name}, %{count} invite', :other => 'Hello %{name}, %{count} invites' }
      }
    })

    assert_equal 'Dear Ada, 2 invitations', I18n.t(:invite, :count => 2, :name => 'Ada', :tone => :formal)
    assert_equal 'Hi Ada, 1 invite', I18n.t(:invite, :count => 1, :name => 'Ada', :tone => :casual)
  end

  test "uses the default variant branch when the selector value is missing or unknown" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => {
        :formal => 'formal %{name}',
        :_default => 'default %{name}'
      }
    })

    assert_equal 'default Ada', I18n.t(:invite, :name => 'Ada')
    assert_equal 'default Ada', I18n.t(:invite, :name => 'Ada', :tone => :unknown)
    assert_equal 'formal Ada', I18n.t(:invite, :name => 'Ada', :tone => :formal)
  end

  test "pluralizes first and then selects a variant inside the plural branch (plural then variant)" do
    store_translations(:en, :invite => {
      :one => {
        :_variant => :tone,
        :_variants => { :formal => 'Dear %{name}, one', :_default => 'Hi %{name}, one' }
      },
      :"1" => {
        :_variant => :tone,
        :_variants => { :formal => 'Dear %{name}, one', :_default => 'Hi %{name}, one' }
      },
      :other => {
        :_variant => :tone,
        :_variants => { :formal => 'Dear %{name}, %{count}', :_default => 'Hi %{name}, %{count}' }
      }
    })

    assert_equal 'Dear Ada, one', I18n.t(:invite, :count => 1, :name => 'Ada', :tone => :formal)
    assert_equal 'Hi Ada, 3', I18n.t(:invite, :count => 3, :name => 'Ada')
  end

  test "supports multiple nested variant dimensions" do
    store_translations(:en, :invite => {
      :_variants => {
        :tone => {
          :formal => {
            :_variants => {
              :person => {
                :first => 'Dear friend',
                :third => 'Dear colleague',
                :_default => 'Dear guest'
              }
            }
          },
          :casual => {
            :_variants => {
              :person => {
                :first => 'Hey friend',
                :_default => 'Hey guest'
              }
            }
          }
        }
      }
    })

    assert_equal 'Dear colleague', I18n.t(:invite, :tone => :formal, :person => :third)
    assert_equal 'Hey friend', I18n.t(:invite, :tone => :casual, :person => :first)
    assert_equal 'Hey guest', I18n.t(:invite, :tone => :casual)
    assert_equal 'Dear guest', I18n.t(:invite, :tone => :formal)
  end

  test "uses a root default for wrapped variants when no dimension is selected" do
    store_translations(:en, :invite => {
      :_variants => {
        :tone => {
          :formal => 'Dear',
          :_default => 'Hi'
        },
        :_default => 'Hello'
      }
    })

    assert_equal 'Hello', I18n.t(:invite)
  end

  test "does not treat an ordinary namespace hash as a variant" do
    store_translations(:en, :mail => {
      :subject => 'Subject',
      :body => 'Body'
    })

    assert_equal({ :subject => 'Subject', :body => 'Body' }, I18n.t(:mail))
    assert_equal 'Subject', I18n.t('mail.subject')
  end

  test "interpolates only the finally selected text" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => {
        :formal => 'Dear %{name}',
        :_default => 'Hi'
      }
    })

    assert_equal 'Hi', I18n.t(:invite)
    assert_equal 'Dear Ada', I18n.t(:invite, :name => 'Ada', :tone => :formal)
  end

  test "returns a mutable copy of the selected string" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => { :formal => 'Dear'.freeze }
    })

    refute_predicate I18n.t(:invite, :tone => :formal), :frozen?
  end

  test "resolves a linked translation selected by a variant" do
    store_translations(:en, {
      :formal_invite => 'Dear %{name}',
      :invite => {
        :_variant => :tone,
        :_variants => { :formal => :formal_invite }
      }
    })

    assert_equal 'Dear Ada', I18n.t(:invite, :name => 'Ada', :tone => :formal)
  end

  test "raises InvalidVariantData with the full path when a required variant value has no branch" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => { :formal => 'formal' }
    })

    error = assert_raises(I18n::InvalidVariantData) do
      I18n.t(:invite, :tone => :casual)
    end
    assert_equal :tone, error.variant
    assert_equal [:en, :invite, :tone, :casual], error.path
  end

  test "reports the plural category selected by custom pluralization rules in the path" do
    rule = lambda do |count|
      count == 11 ? :many : :other
    end
    store_translations(:en, :i18n => { :plural => { :rule => rule } })
    store_translations(:en, :invite => {
      :other => {
        :_variant => :tone,
        :_variants => { :formal => 'formal', :_default => 'other default' }
      },
      :many => {
        :_variant => :tone,
        :_variants => { :formal => 'many formal' }
      }
    })

    error = assert_raises(I18n::InvalidVariantData) do
      I18n.t(:invite, :count => 11)
    end
    assert_equal [:en, :invite, :many, :tone, :_default], error.path
  end

  test "falls back to another locale for a missing variant translation" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => { :formal => 'Dear %{name}', :_default => 'Hello %{name}' }
    })

    assert_equal 'Dear Ada', I18n.t(:invite, :name => 'Ada', :tone => :formal, :locale => :de)
    assert_equal 'Hello Ada', I18n.t(:invite, :name => 'Ada', :locale => :de)
  end

  test "falls back when the selected variant branch is explicitly nil in the locale" do
    store_translations(:en, :invite => {
      :_variant => :tone,
      :_variants => { :formal => 'Dear %{name}', :_default => 'Hello %{name}' }
    })
    store_translations(:de, :invite => {
      :_variant => :tone,
      :_variants => { :formal => nil, :_default => 'Hallo %{name}' }
    })

    assert_equal 'Dear Ada', I18n.t(:invite, :name => 'Ada', :tone => :formal, :locale => :de)
  end
end
