# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/citadele/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-citadele'
  spec.version       = Omniauth::Citadele::VERSION
  spec.authors       = ['MAK IT']
  spec.email         = ['admin@makit.lv' ]
  spec.description   = %q{OmniAuth strategy for Citadele Banklink}
  spec.summary       = %q{OmniAuth strategy for Citadele Banklink}
  spec.homepage      = 'https://github.com/mak-it/omniauth-citadele'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.3.0'

  spec.add_runtime_dependency 'omniauth', '~> 1.0'
  spec.add_runtime_dependency 'i18n'

  spec.add_development_dependency 'rack-test'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'

  spec.add_dependency 'xmldsig'
  spec.add_dependency 'nokogiri'
end
