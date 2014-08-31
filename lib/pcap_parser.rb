require "pcap_parser/version"
require "pcap_parser/stream"
require "pcap_parser/save_file"
require "pcap_parser/packet"
require "pcap_parser/linktype"
require "pcap_parser/ethertype"
require "pcap_parser/proto"


module PcapParser
  # Exceptions

  # Raise when pcap file is invalid
  class InvalidPcapFile < StandardError;end

  # Raise when pcap file is too short
  class PcapFileTooShort < StandardError; end

  # Raise when link type is not supported
  class LinkTypeNotSupported < StandardError; end

  # Raise when ether type is not supported
  class EtherTypeNotSupported < StandardError; end
end
