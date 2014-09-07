require 'spec_helper'
describe "read pcap files" do
  it "ICMP proto" do
    expected_data = [
      {time:"17:41:16", mac_src:"84:38:35:44:b3:6a", mac_dst:"b4:75:0e:fa:52:5d",ip_src:"192.168.1.140",ip_dst:"206.126.112.177",type:8},
      {time:"17:41:16", mac_src:"b4:75:0e:fa:52:5d", mac_dst:"84:38:35:44:b3:6a",ip_src:"206.126.112.177",ip_dst:"192.168.1.140",type:0},
      {time:"17:41:17", mac_src:"84:38:35:44:b3:6a", mac_dst:"b4:75:0e:fa:52:5d",ip_src:"192.168.1.140",ip_dst:"206.126.112.177",type:8},
      {time:"17:41:17", mac_src:"b4:75:0e:fa:52:5d", mac_dst:"84:38:35:44:b3:6a",ip_src:"206.126.112.177",ip_dst:"192.168.1.140",type:0},
      {time:"17:41:18", mac_src:"84:38:35:44:b3:6a", mac_dst:"b4:75:0e:fa:52:5d",ip_src:"192.168.1.140",ip_dst:"206.126.112.177",type:8},
      {time:"17:41:18", mac_src:"b4:75:0e:fa:52:5d", mac_dst:"84:38:35:44:b3:6a",ip_src:"206.126.112.177",ip_dst:"192.168.1.140",type:0},
      {time:"17:41:19", mac_src:"84:38:35:44:b3:6a", mac_dst:"b4:75:0e:fa:52:5d",ip_src:"192.168.1.140",ip_dst:"206.126.112.177",type:8},
      {time:"17:41:19", mac_src:"b4:75:0e:fa:52:5d", mac_dst:"84:38:35:44:b3:6a",ip_src:"206.126.112.177",ip_dst:"192.168.1.140",type:0},
      {time:"17:41:27", mac_src:"b4:75:0e:fa:52:5d", mac_dst:"84:38:35:44:b3:6a",ip_src:"192.168.1.1",ip_dst:"192.168.1.140",type:11}
    ]
    PcapParser.read(pcap_sample("icmp")) do |pcap|
      d = expected_data.shift
      # Packet arrive time
      expect( Time.at(pcap.packet.sec).strftime("%H:%M:%S")).to eq(d[:time])
      # source mac address
      expect(pcap.linktype.mac_src).to eq(d[:mac_src])
      # destination mac address
      expect(pcap.linktype.mac_dest).to eq(d[:mac_dst])
      # source ip address
      expect(pcap.ethertype.ip_src).to eq(d[:ip_src])
      # destination ip address
      expect(pcap.ethertype.ip_dst).to eq(d[:ip_dst])
      # protocol
      expect(pcap.proto).to be_kind_of(Proto::ICMP)
      # ICMP packet type
      expect(pcap.proto.type).to eq(d[:type])
      # ICMP packet code
      expect(pcap.proto.code).to eq(0)

      expect(pcap.proto).to be_valid
    end
  end

  it "TCP proto" do
    expected_data = [
      {time:"17:28:35",macs:"84:38:35:44:b3:6a",macd:"b4:75:0e:fa:52:5d",len:78,ips:"192.168.1.140",ports:62862,ipd:"208.80.154.224",portd:80},
      {time:"17:28:35",macs:"b4:75:0e:fa:52:5d",macd:"84:38:35:44:b3:6a",len:74,ips:"208.80.154.224",ports:80,ipd:"192.168.1.140",portd:62862},
      {time:"17:28:35",macs:"84:38:35:44:b3:6a",macd:"b4:75:0e:fa:52:5d",len:66,ips:"192.168.1.140",ports:62862,ipd:"208.80.154.224",portd:80},
      {time:"17:28:35",macs:"84:38:35:44:b3:6a",macd:"b4:75:0e:fa:52:5d",len:980,ips:"192.168.1.140",ports:62862,ipd:"208.80.154.224",portd:80},
      {time:"17:28:35",macs:"b4:75:0e:fa:52:5d",macd:"84:38:35:44:b3:6a",len:66,ips:"208.80.154.224",ports:80,ipd:"192.168.1.140",portd:62862},
      {time:"17:28:35",macs:"b4:75:0e:fa:52:5d",macd:"84:38:35:44:b3:6a",len:1506,ips:"208.80.154.224",ports:80,ipd:"192.168.1.140",portd:62862},
      {time:"17:28:35",macs:"b4:75:0e:fa:52:5d",macd:"84:38:35:44:b3:6a",len:1506,ips:"208.80.154.224",ports:80,ipd:"192.168.1.140",portd:62862}
    ]
    PcapParser.read(pcap_sample("tcp_http")) do |pcap|
      d = expected_data.shift
      expect( Time.at(pcap.packet.sec).strftime("%H:%M:%S")).to eq(d[:time])
      # packet length 
      expect(pcap.packet.cap_len).to eq(d[:len])
      # source mac address
      expect(pcap.linktype.mac_src).to eq(d[:macs])
      # destination mac address
      expect(pcap.linktype.mac_dest).to eq(d[:macd])
      # source ip address
      expect(pcap.ethertype.ip_src).to eq(d[:ips])
      # destination ip address
      expect(pcap.ethertype.ip_dst).to eq(d[:ipd])
      # protocol
      expect(pcap.proto).to be_kind_of(Proto::TCP)
      # source port
      expect(pcap.proto.port_src).to eq(d[:ports])
      # destination port
      expect(pcap.proto.port_dst).to eq(d[:portd])
    end
  end

  it "UDP proto" do
    expected_data = [
      {time:"01:54:46",macs:"00:0f:35:9a:c4:00",macd:"00:50:56:bc:4f:b4",udplen:786,ips:"10.132.88.62",ipd:"10.130.8.20",data:"REGISTER sip"},
      {time:"01:54:46",macs:"00:50:56:bc:4f:b4",macd:"00:00:0c:07:ac:02",udplen:474,ips:"10.130.8.20",ipd:"10.132.88.62",data:"SIP/2\.0 401"},
      {time:"01:54:51",macs:"00:0f:35:9a:c4:00",macd:"00:50:56:bc:4f:b4",udplen:12,ips:"10.164.121.7",ipd:"10.130.8.20"},
      {time:"01:54:51",macs:"00:0f:35:09:e4:00",macd:"00:50:56:bc:4f:b4",udplen:966,ips:"10.160.160.71",ipd:"10.130.8.20",data:"REGISTER sip"},
      {time:"01:54:51",macs:"00:50:56:bc:4f:b4",macd:"00:00:0c:07:ac:02",udplen:547,ips:"10.130.8.20",ipd:"10.160.160.71",data:"SIP/2\.0 401"}
    ]
    
    PcapParser.read(pcap_sample("udp_sip")) do |pcap|
      d = expected_data.shift
      # Packet arrive time
      expect( Time.at(pcap.packet.sec).strftime("%H:%M:%S")).to eq(d[:time])
      # source mac address
      expect(pcap.linktype.mac_src).to eq(d[:macs])
      # destination mac address
      expect(pcap.linktype.mac_dest).to eq(d[:macd])
      # source ip address
      expect(pcap.ethertype.ip_src).to eq(d[:ips])
      # destination ip address
      expect(pcap.ethertype.ip_dst).to eq(d[:ipd])
      # protocol
      expect(pcap.proto).to be_kind_of(Proto::UDP)
      # length
      expect(pcap.proto.length).to eq(d[:udplen])
      # UDP checksum
      expect(pcap.proto).to be_valid
      # data
      if d[:data]
        expect(pcap.proto.data).to match(%r{^#{d[:data]}})
      end
    end
  end
end
