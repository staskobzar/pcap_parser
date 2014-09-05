require_relative 'proto/udp'
require_relative 'proto/tcp'
module PcapParser
  module Proto;end

  PROTO = {
    0x11 => Proto::UDP,
    0x06 => Proto::TCP
  }
end

