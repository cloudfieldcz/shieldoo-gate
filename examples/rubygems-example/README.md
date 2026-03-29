# RubyGems Example -- rake

Installs `rake` via the Shieldoo Gate RubyGems proxy and verifies the dependency resolution.

## Prerequisites

- Ruby 3.0+ (`ruby -v`)
- Bundler 2.0+ (`bundler -v`)
- Shieldoo Gate running locally with the RubyGems proxy enabled on port `8086`

## Run

```bash
# Install dependencies through the Shieldoo proxy
bundle install

# Verify rake is available
bundle exec rake --version
```

Or download a gem directly:

```bash
gem install rake --source http://localhost:8086
```

## What This Tests

- RubyGems proxy on `localhost:8086` correctly proxies rubygems.org API metadata and gem files
- Gem download (`rake-13.1.0.gem`) goes through the scan pipeline
- Check the admin UI at `http://localhost:8080` to see the scanned artifacts
