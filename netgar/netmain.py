import pyshark


def network_conversation(packet):
    try:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        return f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}'
    except AttributeError as e:
        pass


capture = pyshark.FileCapture('live.pcap')
conversations = []
for packet in capture:
    results = network_conversation(packet)
    if results != None:
        conversations.append(results)

# this sorts the conversations by protocol
# TCP and UDP
for item in sorted(conversations):
    print(item)
