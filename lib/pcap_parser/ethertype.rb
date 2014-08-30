require_relative 'ethertype/ipv4'
module PcapParser
  module Ethertype;end

  ETHER_TYPE = {
    0x0800 => Ethertype::IPv4
  }
end

