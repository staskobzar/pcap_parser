module PcapParser
  module Linktype
    class Ethernet
      def initialize(stream)
        @stream = stream
      end

      def read
        @dest_mac = @stream.read_char(6)
        @src_mac = @stream.read_char(6)
        @ether_raw = @stream.read_char(2)
        self
      end
    end
  end
end
