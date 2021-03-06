# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pcap_parser/version'

Gem::Specification.new do |spec|
  spec.name          = "pcap_parser"
  spec.version       = PcapParser::VERSION
  spec.authors       = ["Stas Kobzar"]
  spec.email         = ["stas@modulis.ca"]
  spec.summary       = %q{Parse pcap files}
  spec.description   = %q{Parsing pcap files created by tcpdump}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "byebug"
  spec.add_development_dependency "simplecov"
end
