require 'test_helper'

class I18nBackendVariantsTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Variants
  end

  def setup
    super
    I18n.backend = Backend.new
    store_translations(:en,
      :invitation => {
        :subject => {
          :__select__ => :tone,
          :formal     => 'You are cordially invited',
          :casual     => 'You are invited!',
          :__default__ => 'You are invited'
        },
        :body => {
          :__select__ => :tone,
          :formal => {
            :one   => 'You may bring %{count} guest',
            :other => 'You may bring %{count} guests'
          },
          :casual => {
            :__select__ => :person,
            :first  => 'I saved you a seat',
            :__default__ => 'We saved you a seat'
          }
        },
        :rsvp => {
          :one => {
            :__select__ => :tone,
            :formal => 'One seat remains',
            :casual => 'One seat left'
          },
          :other => {
            :__select__ => :tone,
            :formal => '%{count} seats remain',
            :casual => '%{count} seats left'
          }
        },
        :required => {
          :__select__ => :tone,
          :formal => 'Required formal',
          :casual => {
            :__select__ => :person,
            :first => 'Required casual first',
            :third => 'Required casual third'
          }
        },
        :uninterpolated => {
          :__select__ => :tone,
          :formal => 'Dear %{name}',
          :casual => 'Hey %{name}, %{missing} would raise here'
        }
      },
      :mailbox => {
        :title => 'Inbox'
      }
    )
  end

  test "selects the branch for the given dimension option" do
    assert_equal 'You are cordially invited', I18n.t(:'invitation.subject', :tone => :formal)
    assert_equal 'You are invited!', I18n.t(:'invitation.subject', :tone => :casual)
  end

  test "accepts string option values" do
    assert_equal 'You are cordially invited', I18n.t(:'invitation.subject', :tone => 'formal')
  end

  test "uses the __default__ branch when no option is given" do
    assert_equal 'You are invited', I18n.t(:'invitation.subject')
  end

  test "uses the __default__ branch when the option matches no branch" do
    assert_equal 'You are invited', I18n.t(:'invitation.subject', :tone => :rude)
  end

  test "does not treat plain namespace Hashes as variants" do
    assert_equal({ :title => 'Inbox' }, I18n.t(:mailbox))
    assert_equal 'Inbox', I18n.t(:'mailbox.title')
  end

  test "raises MissingVariantOption with the lookup path when a required option is missing" do
    error = assert_raises(I18n::MissingVariantOption) { I18n.t(:'invitation.required') }
    assert_equal :tone, error.dimension
    assert_includes error.message, 'en.invitation.required'
  end

  test "raises MissingVariantOption when the option matches no branch and no default exists" do
    error = assert_raises(I18n::MissingVariantOption) { I18n.t(:'invitation.required', :tone => :rude) }
    assert_includes error.message, 'en.invitation.required'
    assert_includes error.message, ':rude'
  end

  test "error path reflects nested selection and scope" do
    error = assert_raises(I18n::MissingVariantOption) do
      I18n.t(:required, :scope => :invitation, :tone => :casual)
    end
    assert_includes error.message, 'en.invitation.required.casual'
  end

  test "resolves pluralization nested under a variant" do
    assert_equal 'You may bring 1 guest', I18n.t(:'invitation.body', :tone => :formal, :count => 1)
    assert_equal 'You may bring 3 guests', I18n.t(:'invitation.body', :tone => :formal, :count => 3)
  end

  test "resolves variants nested under pluralization" do
    assert_equal 'One seat remains', I18n.t(:'invitation.rsvp', :tone => :formal, :count => 1)
    assert_equal '5 seats left', I18n.t(:'invitation.rsvp', :tone => :casual, :count => 5)
  end

  test "resolves nested dimensions" do
    assert_equal 'I saved you a seat', I18n.t(:'invitation.body', :tone => :casual, :person => :first)
    assert_equal 'We saved you a seat', I18n.t(:'invitation.body', :tone => :casual)
  end

  test "only interpolates the finally selected text" do
    assert_equal 'Dear Anna', I18n.t(:'invitation.uninterpolated', :tone => :formal, :name => 'Anna')
    error = assert_raises(I18n::MissingInterpolationArgument) do
      I18n.t(:'invitation.uninterpolated', :tone => :casual, :name => 'Anna')
    end
    assert_equal :missing, error.key
  end
end

class I18nBackendVariantsFallbackTest < I18n::TestCase
  class Backend < I18n::Backend::Simple
    include I18n::Backend::Variants
    include I18n::Backend::Fallbacks
  end

  def setup
    super
    I18n.backend = Backend.new
    I18n.fallbacks = I18n::Locale::Fallbacks.new(:de => [:de, :en])
    store_translations(:en,
      :invitation => {
        :subject => {
          :__select__ => :tone,
          :formal => 'You are cordially invited',
          :__default__ => 'You are invited'
        }
      },
      :farewell => {
        :__select__ => :tone,
        :formal => 'Goodbye',
        :casual => 'Bye'
      }
    )
    store_translations(:de,
      :invitation => {
        :subject => {
          :__select__ => :tone,
          :formal => 'Sie sind herzlich eingeladen'
        }
      }
    )
  end

  test "selects variants in the requested locale" do
    assert_equal 'Sie sind herzlich eingeladen', I18n.t(:'invitation.subject', :locale => :de, :tone => :formal)
  end

  test "applies selection after falling back to another locale" do
    assert_equal 'Goodbye', I18n.t(:farewell, :locale => :de, :tone => :formal)
    assert_equal 'Bye', I18n.t(:farewell, :locale => :de, :tone => :casual)
  end

  test "does not fall back when the key exists but a required option is missing" do
    error = assert_raises(I18n::MissingVariantOption) do
      I18n.t(:'invitation.subject', :locale => :de)
    end
    assert_includes error.message, 'de.invitation.subject'
  end
end
