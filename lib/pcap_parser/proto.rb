require_relative 'proto/udp'
require_relative 'proto/tcp'
require_relative 'proto/icmp'
module PcapParser
  module Proto;end

  PROTO = {
    0x01 => Proto::ICMP,
    0x06 => Proto::TCP,
    0x11 => Proto::UDP,
  }
end
