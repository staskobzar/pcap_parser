require "pcap_parser/version"
require "pcap_parser/stream"
require "pcap_parser/save_file"
require "pcap_parser/packet"
require "pcap_parser/linktype"


module PcapParser
  LINK_TYPE = {
    1 => Linktype::Ethernet
  }
  # Exceptions

  # Raise when pcap file is invalid
  class InvalidPcapFile < StandardError;end

  # Raise when pcap file is too short
  class PcapFileTooShort < StandardError; end

  # Raise when link type is not supported
  class LinkTypeNotSupported < StandardError; end
end
