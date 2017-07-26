import pcap
import dpkt

sniffer = pcap.pcap(name=None, promisc=True, immediate=True)

for timestamp, raw_buf in sniffer:
    output = {}

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(raw_buf)
    output['eth0'] = {'src': eth.src, 'dst': eth.dst, 'type':eth.type}

    # It this an IP packet?
    if not isinstance(eth.data, dpkt.ip.IP):
        print ('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        continue 

    # Grab ip packet
    packet = eth.data

    # Pull out fragment information
    df = bool(packet.off & dpkt.ip.IP_DF)
    mf = bool(packet.off & dpkt.ip.IP_MF)
    offset = packet.off & dpkt.ip.IP_OFFMASK

    # Pulling out src, dst, length, fragment info, TTL, checksum and Protocol
    output['ip'] = {'src':packet.src, 'dst':packet.dst, 'p': packet.p,
                    'len':packet.len, 'ttl':packet.ttl,
                    'df':df, 'mf': mf, 'offset': offset,
                    'checksum': packet.sum}
    print (output)