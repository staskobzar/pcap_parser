module PcapParser
  module Linktype
    class Ethernet

      LENGTH = 14

      def initialize(stream)
        @stream = stream
      end

      def read
        @dest_mac = @stream.read_char(6)
        @src_mac = @stream.read_char(6)
        @ether_raw = @stream.read_char(2)
        self
      end

      def mac_dest_raw
        @dest_mac
      end

      def mac_src_raw
        @src_mac
      end

      def mac_dest; mac2str @dest_mac; end
      def mac_src; mac2str @src_mac; end

      def mac2str(mac)
        mac.map{|o| "%02x" % o}.join ?:
      end

      def ether_type
        ether=@stream.little_endian? ? @ether_raw.reverse : @ether_raw
        ethertype=ether.map.with_index{|x,i| x<<(i<<3) }.inject :+
        raise EtherTypeNotSupported if ETHER_TYPE[ethertype].nil?
        ethertype
      end

    end
  end
end
