module PcapParser
  module Linktype
    # Ethernet frame
    # see: http://en.wikipedia.org/wiki/Ethernet_frame#Structure
    class Ethernet
      # Ethernet packet length in bytes
      LENGTH = 14

      def initialize(stream)
        @stream = stream
      end

      # Read whole packet structure.
      # @return [Linktype::Ethernet]
      def read
        @dest_mac = @stream.read_char(6)
        @src_mac = @stream.read_char(6)
        @ether_raw = @stream.read_char(2)
        self
      end

      # Destination mac address
      # @return [Array] Char array
      def mac_dest_raw
        @dest_mac
      end

      # Source mac address
      # @return [Array] Char array
      def mac_src_raw
        @src_mac
      end

      # Human readable destination mac address.
      # @return [String] mac address like 00:22:33:aa:bb:cc
      def mac_dest
        mac2str @dest_mac
      end

      # Human readable source mac address.
      # @return [String] mac address like 00:22:33:aa:bb:cc
      def mac_src
        mac2str @src_mac
      end

      # Convert raw array of chars to human readable mac address.
      # @param mac [Array]
      # @return [String]
      def mac2str(mac)
        mac.map { |o| "%02x" % o }.join ?:
      end

      # Ether type class reference.
      # @return [Object] see lib/pcap_parser/ethertype.rb.
      #                   For example Ethernet::IPv4
      def ether_type
        ether = @stream.little_endian? ? @ether_raw.reverse : @ether_raw
        ethertype = ether.map.with_index { |x, i| x<<(i<<3) }.inject :+
        raise EtherTypeNotSupported if ETHER_TYPE[ethertype].nil?
        ethertype
      end
    end
  end
end
