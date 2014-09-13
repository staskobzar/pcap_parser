require_relative 'proto/udp'
require_relative 'proto/tcp'
require_relative 'proto/icmp'
module PcapParser
  module Proto

    # Calculate sum of all 16bit integers in packet
    # as one's complement 16bit integer.
    # Used to calculate check sum  RFC 1071.
    # @param packet [Array] array of 16bit integers
    # @return [Integer]
    def self.sum_pack_16int(packet)
      packet.reduce(0) do |res, x|
        ((res + x)>>0x10) + ((res + x) & 0xffff)
      end
    end
  end

  PROTO = {
    0x01 => Proto::ICMP,
    0x06 => Proto::TCP,
    0x11 => Proto::UDP,
  }
end
