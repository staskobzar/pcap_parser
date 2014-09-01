module PcapParser
  module Ethertype

    # IP protocal version 4
    # Always big-endian (networking) byte order
    class IPv4

      attr_reader :options
      # IPv4 header length is 20 bytes
      LENGTH = 20

      def initialize(hex_string)
        @hexstr=hex_string
      end

      def version
        @hexstr[0].unpack("C").pop >> 4
      end

      # Return length in bytes
      # IHL * 32 = TOTAL bits / 8 = TOTAL bytes
      # * 32 == shift left 5
      # / 8  == shift right 3
      def header_len
        (@hexstr[0].unpack("C").pop & 0b1111) << 2
      end

      def has_opts?
        self.header_len > 20
      end

      def tos
        @hexstr[1].unpack("C").pop >> 2
      end

      def congestion?
        # last 2 bits
        (@hexstr[1].unpack("C").pop & 0b11) > 0
      end

      def length
        @hexstr[2..3].unpack("n").pop
      end

      def id
        @hexstr[4..5].unpack("n").pop
      end

      # first 3 bit of 16b Int
      def flag
        @hexstr[6..7].unpack("n").pop >> 13
      end

      # last 13 bit of 16b Int
      def frag_offset
        @hexstr[6..7].unpack("n").pop & 0x1fff
      end

      def ttl
        @hexstr[8].unpack("C").pop
      end

      def proto
        @hexstr[9].unpack("C").pop
      end

      def chsum
        @hexstr[10..11].unpack("n").pop
      end

      # Check if packet corrupted using check sum
      # http://en.wikipedia.org/wiki/IPv4_header_checksum
      def valid?
        sum = @hexstr.unpack("n*").inject :+
        ((sum>>16) + (sum & 0xffff)) == 0xffff
      end

      def proto_supported?
        PROTO.keys.include? proto
      end

      def ip_src_long
        @hexstr[12..15].unpack("N").pop
      end

      def ip_dst_long
        @hexstr[16..20].unpack("N").pop
      end

      def ip_src;int2ip ip_src_long;end
      def ip_dst;int2ip ip_dst_long;end

      # Human readable IP address
      def int2ip(ip_int)
        Array(0..3).reverse.
          map{|x| (ip_int >>(x<<3)) & 0xff}.
          join ?.
      end

      # set options
      def options=(hex)
        @options = hex.unpack("n")
      end
    end
  end
end
