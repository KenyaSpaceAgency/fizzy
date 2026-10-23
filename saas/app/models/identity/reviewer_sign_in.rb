# A fixed sign-in code for exactly one identity: the shared reviewer that the
# AI directory listings (Claude, ChatGPT) and the app stores sign in as. Their
# reviewers sign in from fresh browsers and can't read the reviewer's inbox for
# the emailed code, and Fizzy has no password to give them.
#
# The reviewer enters the identity's email address as anyone does, then this
# code in place of the emailed one. Nothing else changes: the emailed code
# still works, and every other identity signs in exactly as before.
#
# Off unless both FIZZY_REVIEWER_SIGN_IN_EMAIL and
# FIZZY_REVIEWER_SIGN_IN_CODE_DIGEST are set. Only the code's SHA-256 digest is
# configured, never the code. Generate both with
# `bin/rails saas:reviewer_sign_in:generate`, which prints a random 16-character
# code (80 bits) and its digest. Rotate the code after each review.
#
# For that one identity the code is the only gate, so its security is exactly
# the code's. Keep the identity in its own comped, internal account.
module Identity::ReviewerSignIn
  CODE_LENGTH = 16

  class << self
    def authenticate(email_address:, code:)
      if matches?(email_address, code)
        Identity.find_by(email_address: configured_email_address).tap do |identity|
          record_use(identity) if identity
        end
      end
    end

    def configured?
      configured_email_address.present? && configured_code_digest.present?
    end

    def digest(code)
      OpenSSL::Digest::SHA256.hexdigest(MagicLink::Code.sanitize(code).to_s)
    end

    def generate_code
      MagicLink::Code.generate(CODE_LENGTH)
    end

    private
      def matches?(email_address, code)
        configured? && \
          email_address.present? && code.present? && \
          ActiveSupport::SecurityUtils.secure_compare(email_address.to_s.downcase, configured_email_address.downcase) && \
          ActiveSupport::SecurityUtils.secure_compare(digest(code), configured_code_digest.downcase)
      end

      def record_use(identity)
        Rails.logger.warn "[ReviewerSignIn] Signed in identity #{identity.id} with the reviewer code"
        Sentry.capture_message "Reviewer sign-in code used", level: :info, extra: { identity_id: identity.id } if defined?(Sentry)
      end

      def configured_email_address
        config.email_address.presence
      end

      def configured_code_digest
        config.code_digest.presence
      end

      def config
        Rails.application.config.x.reviewer_sign_in
      end
  end
end
