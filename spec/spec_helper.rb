$:.unshift File.expand_path('..', __FILE__)
$:.unshift File.expand_path('../../lib', __FILE__)
require 'rspec'
require 'rack/test'
require 'omniauth'
require 'omniauth-citadele'

RSpec.configure do |config|
  config.add_setting('cert_folder')
  config.cert_folder = File.expand_path('../certs', __FILE__)

  config.include Rack::Test::Methods
  config.extend  OmniAuth::Test::StrategyMacros, :type => :strategy
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

I18n.enforce_available_locales = false
