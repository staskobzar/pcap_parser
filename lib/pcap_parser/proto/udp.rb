module PcapParser
  module Proto
    # UDP protocol from transport layer.
    # see: http://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
    # Reads packet as Big-Endian (network byte order)
    class UDP
      def initialize(bin_header)
        @binhdr = bin_header
      end

      # Source port
      # @return [Integer] Big-Endian 16bit int
      def port_src
        @binhdr[0, 2].unpack("n").pop
      end

      # Destination port
      # @return [Integer] Big-Endian 16bit int
      def port_dst
        @binhdr[2, 2].unpack("n").pop
      end

      # Length in bytes of the UDP header and UDP data.
      # @return [Integer] Big-Endian 16bit int
      def length
        @binhdr[4, 2].unpack("n").pop
      end

      # Packet checksum
      # @return [Integer] Big-Endian 16bit int
      def chsum
        @binhdr[6, 2].unpack("n").pop
      end

      # UDP segment data.
      # @return [String]
      def data
        @binhdr[8..-1].unpack("a*").pop
      end

      # Validate packet checksum
      # http://en.wikipedia.org/wiki/User_Datagram_Protocol
      # @return [true,false]
      def valid?
        return true if chsum == 0
        sum = Proto::sum_pack_16int @binhdr.unpack("n4")
        # flit bits in result sum
        # result is th two's complement so to convert we remove 1
        flipped = [sum * -1].pack("n").unpack("n").pop - 1
        0xffff == flipped + sum
      end
    end
  end
end
