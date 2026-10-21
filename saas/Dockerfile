# Make sure RUBY_VERSION matches the Ruby version in .ruby-version
ARG RUBY_VERSION=3.4.8
FROM registry.docker.com/library/ruby:$RUBY_VERSION-slim AS base

# Rails app lives here
WORKDIR /rails

# Set production environment
ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    SAAS="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_GEMFILE="Gemfile.saas" \
    BUNDLE_WITHOUT="development"


# Throw-away build stage to reduce size of final image
FROM base AS build

# Install packages needed to build gems
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends -y build-essential pkg-config git libvips libyaml-dev libssl-dev && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# Install application gems
COPY Gemfile Gemfile.lock Gemfile.saas Gemfile.saas.lock .ruby-version ./
COPY lib/fizzy.rb ./lib/fizzy.rb
COPY saas/fizzy-saas.gemspec ./saas/
COPY saas/lib/fizzy/saas/version.rb ./saas/lib/fizzy/saas/
RUN --mount=type=secret,id=GITHUB_TOKEN --mount=type=cache,id=fizzy-permabundle-${RUBY_VERSION},sharing=locked,target=/permabundle \
    gem install bundler && \
    BUNDLE_PATH=/permabundle BUNDLE_GITHUB__COM="$(cat /run/secrets/GITHUB_TOKEN):x-oauth-basic" bundle install && \
    cp -a /permabundle/. "$BUNDLE_PATH"/ && \
    bundle clean --force && \
    rm -rf "$BUNDLE_PATH"/ruby/*/bundler/gems/*/.git && \
    find "$BUNDLE_PATH" -type f \( -name '*.gem' -o -iname '*.a' -o -iname '*.o' -o -iname '*.h' -o -iname '*.c' -o -iname '*.hpp' -o -iname '*.cpp' \) -delete && \
    bundle exec bootsnap precompile --gemfile

# Copy application code
COPY . .

# Precompile bootsnap code for faster boot times
RUN bundle exec bootsnap precompile app/ lib/

# Precompiling assets for production
RUN SECRET_KEY_BASE_DUMMY=1 \
    ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY=1 \
    ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY=1 \
    ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT=1 \
    ./bin/rails assets:precompile

# Final stage for app image
FROM base

# Install packages needed for deployment. No libvips, ffmpeg or mupdf-tools: every conversion runs
# in the hotcell cell, whose image carries its own. Rails' active_storage/vips tolerates the missing
# library (ActiveStorage::VIPS_AVAILABLE=false), and config/initializers/vips.rb only demands it
# when no cell is registered.
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y ca-certificates libsqlite3-0 sqlite3 libjemalloc-dev && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# The eMudhra intermediate CAs' private keys leaked in October 2026, and they chain to these two roots.
# OpenSSL checks no revocation, so Ruby trusts whatever they sign until the roots leave the bundle.
# ca-certificates is named in an apt-get install above, so a rebuild takes the distro's fixed package
# rather than the one frozen into the base image. Fail the build if either root survives where Ruby's
# OpenSSL looks for them.
RUN ruby -ropenssl -e ' \
  file = ENV[OpenSSL::X509::DEFAULT_CERT_FILE_ENV] || OpenSSL::X509::DEFAULT_CERT_FILE; \
  dir = ENV[OpenSSL::X509::DEFAULT_CERT_DIR_ENV] || OpenSSL::X509::DEFAULT_CERT_DIR; \
  pems = [file, *Dir.glob(File.join(dir, "*"))].select { |path| File.file?(path) } \
    .flat_map { |path| File.read(path).scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m) }; \
  subjects = pems.map { |pem| OpenSSL::X509::Certificate.new(pem).subject.to_s }.uniq; \
  abort "Only #{subjects.size} roots in #{file} and #{dir}" if subjects.size < 100; \
  distrusted = subjects.grep(%r{/CN=(emSign ECC Root CA - G3|AAA Certificate Services)\z}); \
  abort "Distrusted roots still trusted: #{distrusted}" if distrusted.any?'

# Copy built artifacts: gems, application
COPY --from=build /usr/local/bundle /usr/local/bundle
COPY --from=build /rails /rails

# Where the hotcell socket volume mounts, owned by the cell's uid rather than this image's user. A new
# named volume takes its ownership from the directory it covers in whichever container mounts it first,
# and on a new host that is the app. Left to Docker to create, it is root-owned and the cell cannot create
# its sockets in it — which fails as EACCES when the accessory boots, with nothing here to say why.
RUN mkdir -p /run/hotcell/active_storage && chown -R 10001:10001 /run/hotcell

# Run and own only the runtime files as a non-root user for security
RUN useradd rails --create-home --shell /bin/bash && \
    chown -R rails:rails db log storage tmp
USER rails:rails

# Entrypoint prepares the database.
ENTRYPOINT ["/rails/bin/docker-entrypoint"]

# Ruby GC tuning values pulled from Autotuner recommendations
ENV RUBY_GC_HEAP_0_INIT_SLOTS=692636 \
    RUBY_GC_HEAP_1_INIT_SLOTS=175943 \
    RUBY_GC_HEAP_2_INIT_SLOTS=148807 \
    RUBY_GC_HEAP_3_INIT_SLOTS=9169 \
    RUBY_GC_HEAP_4_INIT_SLOTS=3054 \
    RUBY_GC_MALLOC_LIMIT=67108864 \
    RUBY_GC_MALLOC_LIMIT_MAX=134217728 \
    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2

# Start the server by default, this can be overwritten at runtime
EXPOSE 80 443 9394
CMD ["./bin/thrust", "./bin/rails", "server"]
