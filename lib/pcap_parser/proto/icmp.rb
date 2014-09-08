module PcapParser
  module Proto
    class ICMP
      def initialize(bin_header)
        @binhdr = bin_header
      end

      def type
        @binhdr[0].unpack("C").pop
      end

      def code
        @binhdr[1].unpack("C").pop
      end

      def chsum
        @binhdr[2, 2].unpack("n").pop
      end

      def valid?
        0xffff == Proto::sum_pack_16int(@binhdr.unpack("n*"))
      end
    end
  end
end
