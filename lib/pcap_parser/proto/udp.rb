module PcapParser
  module Proto
    class UDP
      def initialize(bin_header)
        @binhdr=bin_header
      end

      def port_src
        @binhdr[0,2].unpack("n").pop
      end

      def port_dst
        @binhdr[2,2].unpack("n").pop
      end

      def length
        @binhdr[4,2].unpack("n").pop
      end

      def chsum
        @binhdr[6,2].unpack("n").pop
      end

      def data
        @binhdr[8..-1].unpack("a*").pop
      end

      # validate packet checksum
      # http://en.wikipedia.org/wiki/User_Datagram_Protocol
      def valid?
        return true if chsum == 0
        sum = @binhdr.unpack("n4").reduce(0) do |res,x| 
          res = ((res + x)>>0x10) + ((res + x) & 0xffff)
        end
        # flit bits in result sum 
        # result is th two's complement so to convert we remove 1
        flipped = [sum * -1].pack("n").unpack("n").pop - 1
        0xffff == flipped + sum
      end
    end
  end
end
