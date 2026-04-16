# RubyGems Example — rake

Installs `rake` via the Shieldoo Gate RubyGems proxy and verifies the dependency resolution.

## Prerequisites

- Ruby 3.0+ (`ruby -v`)
- Bundler 2.0+ (`bundler -v`)
- Shieldoo Gate running locally with the RubyGems proxy enabled on port `8086`

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known **development token** (`test-token-123`) and the **project label** `rubygems-demo`.

RubyGems/Bundler supports HTTP Basic auth via userinfo in the source URL. The bundled `Gemfile` already contains:

```ruby
source "http://rubygems-demo:test-token-123@localhost:8086"
```

- `rubygems-demo` is the **project label** (Basic auth username).
- `test-token-123` is the shared dev token (Basic auth password).

For production, prefer `bundle config set --local <source> <user>:<token>` so the credentials never land in `Gemfile`.

## Run

```bash
# Install dependencies through the Shieldoo proxy
bundle install

# Verify rake is available
bundle exec rake --version
```

Or download a gem directly (note the embedded auth):

```bash
gem install rake --source http://rubygems-demo:test-token-123@localhost:8086
```

## What This Tests

- RubyGems proxy on `localhost:8086` correctly proxies rubygems.org API metadata and gem files
- The Basic-auth username `rubygems-demo` is resolved to a `projects` row
- Gem download (`rake-13.x.x.gem`) goes through the scan pipeline and is stamped with `project_id = rubygems-demo` in the audit log
- Verify in the admin UI at `http://localhost:8080`:
  - `Projects` tab → `rubygems-demo` with its artifact usage
  - `Audit Log` tab → each gem fetch tagged with the project
