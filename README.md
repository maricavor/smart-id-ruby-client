# smart_id

Ruby client gem for integrating Smart-ID into Ruby applications.

## Installation

Install the gem and add to the application's Gemfile:

```bash
bundle add smart_id
```

Or install it directly:

```bash
gem install smart_id
```

## Usage

```ruby
require "smart_id"
```

## Logging

The library uses `SmartId.logger` for connector-level logs.
By default, logger level is `WARN`.

```ruby
require "logger"
require "smart_id"

SmartId.logger = Logger.new($stdout)
SmartId.logger.level = Logger::DEBUG
```

At `DEBUG` level, request lifecycle logs include HTTP method, URL and response status.
Request/response bodies are not logged by default.

## Development

After checking out the repo, run:

```bash
bin/setup
bundle exec rake
```

## License

The gem is available as open source under the terms of the MIT License.
