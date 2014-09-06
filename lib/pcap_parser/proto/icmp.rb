module PcapParser
  module Proto
    class ICMP
      def initialize(bin_header)
        @binhdr=bin_header
      end

      def type
        @binhdr[0].unpack("C").pop
      end

      def code
        @binhdr[1].unpack("C").pop
      end

      def chsum
        @binhdr[2,2].unpack("n").pop
      end

      def valid?
        0xffff == @binhdr.unpack("n*").reduce(0) do |res,x| 
          res = ((res + x)>>0x10) + ((res + x) & 0xffff)
        end 
      end
    end
  end
end

