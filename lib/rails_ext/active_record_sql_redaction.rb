# Trilogy runs without prepared statements, so a value reaches the SQL text as a quoted literal, and with
# Rails.event in debug mode (config/application.rb) that text reaches the log: in SaaS mode, the structured
# log line for the request or job, and from there Loki. Sentry breadcrumbs carry it too, and a database
# error can quote a value in its message. SQLite runs with prepared statements and logs the value as a bind.
#
# For the tables listed here every literal and every bind is secret enough to drop:
#
#   account_join_codes.code         joins whoever holds it to the account
#   identity_access_tokens.token    API bearer token
#   identity_transfers.token        signs its holder in as the identity
#   magic_links.code                signs its holder in as the identity
#   webhooks.signing_secret, .url   signs payloads; a chat webhook URL is itself a credential
#
# Filtering by table rather than column keeps INSERT ... VALUES, multi-row inserts and IN lists covered
# without parsing column positions. The statement sent to the database is never changed: only what is
# logged, reported or raised about it.
#
# A new secret-bearing column on another table fails test/lib/rails_ext/active_record_sql_redaction_test.rb
# until it is listed here or declared not secret there.
module ActiveRecordSqlRedaction
  STRING_LITERAL = /'(?:[^'\\]|\\.|'')*'/
  FILTERED = "[FILTERED]"
  FILTERED_LITERAL = "'#{FILTERED}'"
  FILTERED_ERROR = "[FILTERED: a statement on a redacted table failed]"

  # A failed CREATE TABLE (1005) quotes no row, and Active Record reads its "errno: 150" to tell a
  # mismatched foreign key, so its message is kept.
  UNFILTERED_ERROR_CODES = [ 1005 ].freeze

  mattr_accessor :tables, default: %w[ account_join_codes identity_access_tokens identity_transfers magic_links webhooks ].freeze

  class << self
    def redact(sql)
      if redacted_statement?(sql)
        sql.gsub(STRING_LITERAL, FILTERED_LITERAL)
      else
        sql
      end
    end

    # A table named as a statement names it: `magic_links` on MySQL, "magic_links" on SQLite.
    def redacted_statement?(sql)
      sql.is_a?(String) && tables.any? { |table| sql.include?("`#{table}`") || sql.include?(%("#{table}")) }
    end

    # Names a redacted table the way SQL and MySQL errors do: a quoted identifier in a statement, or
    # the key a duplicate entry collided on (MySQL 8 writes magic_links.index_magic_links_on_code, older
    # servers index_magic_links_on_code). Not a bare word or a path, so a route error for /join/... keeps
    # its message.
    def mentions_redacted_table?(text)
      text.is_a?(String) && tables.any? { |table| text.match?(reference_to(table)) }
    end

    # A server error on such a statement can quote the row's values (a duplicate-entry error quotes the
    # entry), and nothing about the wording is safe to parse, so the whole message is replaced. Every sink
    # that reads the error afterwards, the translated Active Record error and its cause alike, sees only
    # the error code.
    def filter_error(error)
      filtered = [ error.error_code, FILTERED_ERROR ].join(": ")
      error.define_singleton_method(:message) { filtered }
      error.define_singleton_method(:to_s) { filtered }
      error.define_singleton_method(:detailed_message) { |**| filtered }
      error
    end

    private
      def reference_to(table)
        name = Regexp.escape(table)
        /`#{name}`|"#{name}"|\b#{name}\.(?:PRIMARY\b|index_)|\bindex_#{name}_/
      end
  end
end

module ActiveRecordSqlRedaction::StructuredEvents
  def emit_debug_event(name, payload = nil, caller_depth: 1, **kwargs)
    if name == "active_record.sql" && ActiveRecordSqlRedaction.redacted_statement?(kwargs[:sql])
      kwargs = kwargs.merge \
        sql: ActiveRecordSqlRedaction.redact(kwargs[:sql]),
        binds: kwargs[:binds]&.map { |bind_name, _| [ bind_name, ActiveRecordSqlRedaction::FILTERED ] }
    end

    super(name, payload, caller_depth: caller_depth + 1, **kwargs)
  end
end

module ActiveRecordSqlRedaction::ErrorTranslation
  private
    # Only errors the server returned carry a code, and only those can echo a value; a lost connection
    # keeps its message, which the adapter reads to classify it.
    def translate_exception_class(native_error, sql, binds)
      if native_error.respond_to?(:error_code) && native_error.error_code && \
          ActiveRecordSqlRedaction::UNFILTERED_ERROR_CODES.exclude?(native_error.error_code) && \
          ActiveRecordSqlRedaction.mentions_redacted_table?(sql)
        ActiveRecordSqlRedaction.filter_error(native_error)
      end

      super
    end
end

ActiveSupport.on_load(:active_record) do
  ActiveRecord::StructuredEventSubscriber.prepend(ActiveRecordSqlRedaction::StructuredEvents)
  ActiveRecord::ConnectionAdapters::AbstractAdapter.prepend(ActiveRecordSqlRedaction::ErrorTranslation)
end
