module PcapParser
  module Proto
    class TCP

      def initialize(bin_header)
        @binhdr=bin_header
      end

      def port_src
        @binhdr[0,2].unpack("n").pop
      end

      def port_dst
        @binhdr[2,2].unpack("n").pop
      end

      def seq
        @binhdr[4,4].unpack("N").pop
      end

      def acknum
        @binhdr[8,4].unpack("N").pop
      end

      def header_len
        (@binhdr[12,1].unpack("C").pop >> 4) << 2
      end

      def [](flag)
        bit = {NS:8, CWR:1, ECE:2, URG:3, ACK:4, PSH:5, RST:6, SYN:7, FIN:8}
        Stream::bit_set?( @binhdr[ flag.eql?(:NS) ? 12 : 13 ], bit[flag])
      end

      def win_size
        @binhdr[14,2].unpack("n").pop
      end

      def chsum
        @binhdr[16,2].unpack("n").pop
      end

      def has_opts?
        header_len > 20
      end

      def data
        @binhdr[header_len..-1].unpack("a*").pop
      end
    end
  end
end
