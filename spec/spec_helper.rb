require 'simplecov'
SimpleCov.start do
  add_filter "/spec/"
end

require 'rspec'
require 'byebug'
require 'pcap_parser'

include PcapParser

Dir["./spec/support/**/*.rb"].each { |f| require f }
RSpec.configure do |cfg|
    cfg.filter_run :focus => true
    cfg.run_all_when_everything_filtered = true
    cfg.expect_with :rspec do |expectations|
    expectations.syntax = :expect
  end
end

def pcap_sample(name)
  File.expand_path("pcap_samples/#{name}.pcap",File.dirname(__FILE__))
end
