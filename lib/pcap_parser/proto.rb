require_relative 'proto/udp'
module PcapParser
  module Proto;end

  PROTO = {
    0x11 => Proto::UDP
  }
end

