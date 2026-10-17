require "test_helper"

class ActiveRecordSqlRedactionTest < ActiveSupport::TestCase
  # Made-up values, distinctive enough that finding one in a log can only mean it leaked.
  CODE = "ZQ7XW3"
  OTHER_CODE = "ZQ7XW4"
  JOIN_CODE = "Zfak-eJoi-nCod"
  TOKEN = "madeUpAccessToken0000000"
  TRANSFER_TOKEN = "madeUpTransferToken00000"
  SECRET = "madeUpSigningSecret00000"
  WEBHOOK_URL = "https://hooks.slack.com/services/T0000/B0000/madeUpWebhookPath0000"

  # Columns whose names look like a credential's but whose values aren't one. A secret-bearing column
  # belongs in ActiveRecordSqlRedaction.tables instead.
  NOT_SECRET = {
    "action_pack_passkeys.credential_id" => "a passkey's public identifier, sent to the browser to sign in",
    "action_pack_passkeys.public_key" => "a public key",
    "action_push_native_devices.token" => "an APNs/FCM device address; pushing to it takes our push credentials",
    "active_storage_blobs.key" => "a storage object's name; reading the object takes a signed URL",
    "active_storage_variant_records.variation_digest" => "a digest of the image transformation",
    "audits1984_auditor_tokens.token_digest" => "a digest; the token itself isn't stored",
    "board_publications.key" => "a published board's public link, which is in its URL path anyway",
    "filters.params_digest" => "a digest of the filter's parameters",
    "push_subscriptions.auth_key" => "Web Push accepts a message only when it is signed with our VAPID key",
    "push_subscriptions.p256dh_key" => "a public key"
  }

  SECRET_LOOKING_COLUMN = /token|code|secret|passw|digest|key|salt|otp|nonce|credential/

  test "a magic link's code is absent from its logged insert, lookup, update and delete" do
    log, executed = capture do
      magic_link = identities(:kevin).magic_links.create!(code: CODE)
      assert_equal magic_link, MagicLink.active.find_by(code: CODE)
      magic_link.update!(code: OTHER_CODE)
      assert_equal magic_link, MagicLink.consume(OTHER_CODE)
    end

    assert_match(/INSERT INTO [`"]magic_links[`"]/, log)
    assert_match(/UPDATE [`"]magic_links[`"]/, log)
    assert_match(/DELETE FROM [`"]magic_links[`"]/, log)
    assert_no_secret CODE, log
    assert_no_secret OTHER_CODE, log
    assert_sent_to_database CODE, executed
    assert_sent_to_database OTHER_CODE, executed
  end

  test "an access token is absent from its logged insert and lookup" do
    log, executed = capture do
      access_token = identities(:kevin).access_tokens.create!(token: TOKEN, permission: "write")
      assert_equal identities(:kevin), Identity.find_by_permissable_access_token(TOKEN, method: "POST")
      access_token.update!(description: "Made-up script")
    end

    assert_match(/INSERT INTO [`"]identity_access_tokens[`"]/, log)
    assert_match(/FROM [`"]identity_access_tokens[`"]/, log)
    assert_no_secret TOKEN, log
    assert_sent_to_database TOKEN, executed
  end

  test "a join code is absent from its logged insert, lookup and reset" do
    join_code = nil

    log, executed = capture do
      join_code = Account::JoinCode.create!(account: accounts(:initech), code: JOIN_CODE)
      assert_equal join_code, Account::JoinCode.find_by(code: JOIN_CODE, account: accounts(:initech))
      join_code.reset
    end

    assert_match(/INSERT INTO [`"]account_join_codes[`"]/, log)
    assert_match(/UPDATE [`"]account_join_codes[`"]/, log)
    assert_no_secret JOIN_CODE, log
    assert_no_secret join_code.code, log
    assert_sent_to_database JOIN_CODE, executed
    assert_sent_to_database join_code.code, executed
  end

  test "a transfer token is absent from its logged insert and lookup" do
    log, executed = capture do
      identities(:kevin).transfers.create!(token: TRANSFER_TOKEN)
      assert_equal identities(:kevin), Identity.find_by_transfer_id(TRANSFER_TOKEN)
    end

    assert_match(/INSERT INTO [`"]identity_transfers[`"]/, log)
    assert_no_secret TRANSFER_TOKEN, log
    assert_sent_to_database TRANSFER_TOKEN, executed
  end

  test "a webhook's signing secret and URL are absent from its logged insert and update" do
    log, executed = capture do
      webhook = Webhook.create!(board: boards(:writebook), name: "Made up", url: "https://example.com/made-up", signing_secret: SECRET)
      webhook.update!(url: WEBHOOK_URL)
    end

    assert_match(/INSERT INTO [`"]webhooks[`"]/, log)
    assert_match(/UPDATE [`"]webhooks[`"]/, log)
    assert_no_secret SECRET, log
    assert_no_secret WEBHOOK_URL, log
    assert_sent_to_database SECRET, executed
  end

  test "statements against other tables keep their literals" do
    log, _ = capture { Identity.find_by(email_address: "made-up@example.com") }

    assert_includes log, "made-up@example.com"
  end

  test "the structured SQL event carries the redacted statement and binds" do
    events = []
    subscriber = Class.new { define_method(:emit) { |event| events << event } }.new
    Rails.event.subscribe(subscriber) { |event| event[:name] == "active_record.sql" }

    MagicLink.find_by(code: CODE)

    payload = events.map { |event| event[:payload] }.find { |payload| payload[:sql].include?("magic_links") }
    assert payload
    assert_no_secret CODE, payload.inspect
  ensure
    Rails.event.unsubscribe(subscriber)
  end

  test "a duplicate entry's error carries no value" do
    identities(:kevin).magic_links.create!(code: CODE)

    error = assert_raises ActiveRecord::RecordNotUnique do
      identities(:kevin).magic_links.new(code: CODE, expires_at: 1.minute.from_now).save!(validate: false)
    end

    [ error.message, error.cause.message, error.full_message, error.cause.detailed_message ].each do |message|
      assert_no_secret CODE, message
    end
    assert_includes error.message, ActiveRecordSqlRedaction::FILTERED_ERROR if error.cause.respond_to?(:error_code)
  end

  test "redaction covers the statement shapes Active Record writes" do
    assert_equal "SELECT * FROM `magic_links` WHERE `code` IN ('[FILTERED]', '[FILTERED]')",
      ActiveRecordSqlRedaction.redact("SELECT * FROM `magic_links` WHERE `code` IN ('a\\'b', 'it''s')")
    assert_equal "INSERT INTO `magic_links` (`id`, `code`) VALUES (x'[FILTERED]', '[FILTERED]'), (x'[FILTERED]', '[FILTERED]')",
      ActiveRecordSqlRedaction.redact("INSERT INTO `magic_links` (`id`, `code`) VALUES (x'01', 'ZQ7XW3'), (x'02', 'ZQ7XW4')")
    assert_equal "INSERT INTO `identity_access_tokens` (`token`) VALUES ('[FILTERED]') ON DUPLICATE KEY UPDATE `token` = '[FILTERED]'",
      ActiveRecordSqlRedaction.redact("INSERT INTO `identity_access_tokens` (`token`) VALUES ('a') ON DUPLICATE KEY UPDATE `token` = 'b'")
    assert_equal %(SELECT "magic_links".* FROM "magic_links" WHERE "magic_links"."code" = '[FILTERED]'),
      ActiveRecordSqlRedaction.redact(%(SELECT "magic_links".* FROM "magic_links" WHERE "magic_links"."code" = 'ZQ7XW3'))
    assert_equal "SELECT 'x' FROM `accounts`", ActiveRecordSqlRedaction.redact("SELECT 'x' FROM `accounts`")
    assert_equal "SELECT 'x' FROM `magic_links_archive`", ActiveRecordSqlRedaction.redact("SELECT 'x' FROM `magic_links_archive`")
    assert_nil ActiveRecordSqlRedaction.redact(nil)
  end

  test "errors are recognized by the tables they name, not by words" do
    assert ActiveRecordSqlRedaction.mentions_redacted_table?("Duplicate entry 'x' for key 'magic_links.index_magic_links_on_code'")
    assert ActiveRecordSqlRedaction.mentions_redacted_table?("Duplicate entry 'x' for key 'index_identity_transfers_on_token'")
    assert ActiveRecordSqlRedaction.mentions_redacted_table?("INSERT INTO `webhooks` (`url`) VALUES ('x')")
    assert_not ActiveRecordSqlRedaction.mentions_redacted_table?("No route matches [GET] \"/my/webhooks\"")
    assert_not ActiveRecordSqlRedaction.mentions_redacted_table?("Duplicate entry 'x' for key 'cards.index_cards_on_number'")
  end

  test "every column that looks secret is redacted or declared not secret" do
    Rails.application.eager_load!

    columns = ActiveRecord::Base.descendants
      .reject { |model| model.abstract_class? || model.name.nil? }
      .uniq(&:table_name)
      .select(&:table_exists?)
      .flat_map { |model| model.column_names.map { |column| "#{model.table_name}.#{column}" } }
      .select { |column| column.split(".").last.match?(SECRET_LOOKING_COLUMN) }

    assert_includes columns, "magic_links.code", "the scan should see the columns it guards"

    unclassified = columns.reject { |column| column.split(".").first.in?(ActiveRecordSqlRedaction.tables) || NOT_SECRET.key?(column) }
    assert_empty unclassified, "Add each table to ActiveRecordSqlRedaction.tables, or the column to NOT_SECRET with a reason"
  end

  private
    def capture
      log = StringIO.new
      executed = []
      logger, ActiveRecord::LogSubscriber.logger = ActiveRecord::LogSubscriber.logger, ActiveSupport::Logger.new(log)
      record = ->(event) { executed << [ event.payload[:sql], *bind_values(event.payload[:type_casted_binds]) ].join(" ") }

      ActiveSupport::Notifications.subscribed(record, "sql.active_record") { yield }

      [ log.string, executed ]
    ensure
      ActiveRecord::LogSubscriber.logger = logger
    end

    def bind_values(binds)
      binds.respond_to?(:call) ? binds.call : Array(binds)
    end

    def assert_no_secret(secret, text)
      assert_not_includes text, secret
    end

    # The database still receives the value: in the SQL text on MySQL, as a bind on SQLite.
    def assert_sent_to_database(secret, executed)
      assert executed.any? { |statement| statement.include?(secret) }, "#{secret} should reach the database"
    end
end
