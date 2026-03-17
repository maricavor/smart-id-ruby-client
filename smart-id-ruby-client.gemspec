# frozen_string_literal: true

require_relative "lib/smart_id_ruby/version"

Gem::Specification.new do |spec|
  spec.name = "smart-id-ruby-client"
  spec.version = SmartIdRuby::VERSION
  spec.authors = ["Sergei Tsõganov"]
  spec.email = ["sergei.tsoganov@internet.ee"]

  spec.summary = "Smart-ID wrapper library for using Smart-ID in Ruby applications"
  spec.homepage = "https://github.com/maricavor/smart-id-ruby-client"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "base64"
  spec.add_dependency "faraday", "~> 2.0"
  spec.add_dependency "rqrcode", "~> 3.0"
end
