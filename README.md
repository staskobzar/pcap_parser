# PcapParser

[![Code Climate](https://codeclimate.com/github/staskobzar/pcap_parser/badges/gpa.svg)](https://codeclimate.com/github/staskobzar/pcap_parser)
[![Test Coverage](https://codeclimate.com/github/staskobzar/pcap_parser/badges/coverage.svg)](https://codeclimate.com/github/staskobzar/pcap_parser)

[![PullReview stats](https://www.pullreview.com/github/staskobzar/pcap_parser/badges/master.svg?)](https://www.pullreview.com/github/staskobzar/pcap_parser/reviews/master)

Simple library to parse libpcap format files with pure ruby. 
This is personal project just to learn deeper network packets structure.
It works pretty well but there are more mature libraries like [PacketFu](https://github.com/packetfu/packetfu) 
with more options.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'pcap_parser', source: 'git@github.com:staskobzar/pcap_parser.git'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install pcap_parser

## Supported protocols
* Link protocols: Ethernet
* Internet protocols: IPv4, ICMP
* Transport protocols: TCP, UDP

## Usage
```ruby
require 'pcap_parser'
PcapParser.read("tcp-pcap-file.pcap") do |pcap|
  # PCAP frame
  puts "Packet reveiver at #{Time.at(pcap.packet.sec).strftime("%H:%M:%S")} microseconds: #{pcap.packet.usec}"
  puts "Packet length is #{pcap.packet.cap_len}"
  # Linktype (Ethernet)
  puts "- Link type #{pcap.linktype.class}"
  puts "- Ethernet source mac: #{pcap.linktype.mac_src}, destination mac: #{pcap.linktype.mac_dest}"
  # Internet protocol
  puts "-- Ethertype protocol #{pcap.ethertype.class}"
  puts "-- Ethertype Source IP: #{pcap.ethertype.ip_src}; Dest IP: #{pcap.ethertype.ip_dst}"
  puts "-- Ethertype packet length: #{pcap.ethertype.length}"
  # Transport protocol (UDP, TCP etc)
  puts "--- Transport protocol #{pcap.proto.class}"
end
```

## Contributing

1. Fork it ( https://github.com/[my-github-username]/pcap_parser/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
