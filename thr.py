import argparse
import os
from time import sleep
import sys
from scapy.utils import PcapReader
from scapy.layers.dot11 import *
from scapy.packet import Packet
from scapy.all import *

def get_data_frames():
    myreader = PcapReader(FILE_NAME)
    for pkt in myreader:
        if Dot11 in pkt and pkt[Dot11].type == 2:
            yield pkt

def get_data_frames_from_to(fromNode, toNode):
    for pkt in get_data_frames():
        DS = pkt[Dot11].FCfield & 0x3
        to_DS = DS & 0x1 != 0
        from_DS = DS & 0x2 != 0

        # If data frame going is going from Client ---> AP:
        if to_DS and not from_DS and pkt[Dot11].addr3 == toNode and pkt[Dot11].addr2 == fromNode:
            yield pkt

def count_all_data_frames():
    count = 0
    for pkt in get_data_frames():
        count = count + 1
    return count

def count_data_frames_from_to(fromNode, toNode):
    count = 0
    frames = get_data_frames_from_to(fromNode, toNode)
    for frame in frames:
        count = count + 1
    return count

def count_all_retry_data_frames():
    count = count_all_data_frames()
    retryCount = 0

    if count == 0:
        return 0

    for pkt in get_data_frames():
        retry_bit = pkt[Dot11].FCfield & 0x8!= 0
        if retry_bit:
            retryCount = retryCount +  1

    if retryCount == 0:
        return 0
    else:
        return retryCount / count

def count_retry_data_frames_from_to(fromNode, toNode):
    count = count_data_frames_from_to(fromNode, toNode)
    frames = get_data_frames_from_to(fromNode, toNode)
    retryCount = 0

    if count == 0:
        return 0

    for pkt in frames:
        retry_bit = pkt[Dot11].FCfield & 0x8!= 0
        if retry_bit:
            retryCount = retryCount + 1

    if retryCount == 0:
        return 0
    else:
        return retryCount / count

def data_frame_bytes_from_to(fromNode, toNode):
    count_bytes = 0
    frames = get_data_frames_from_to(fromNode, toNode)
    for pkt in frames: 
        count_bytes = count_bytes + len(pkt[Dot11].payload) ##Seems to give 10 more bytes than what is present in the payload. Might be because of a header. 
    return count_bytes

def process_pcap(AP, CLIENT):
    print("All data frames:", count_all_data_frames())
    print("Data frames", CLIENT, '(client) ---->', AP, '(AP):', count_data_frames_from_to(CLIENT, AP))
    print("\nPercentage of re-transmitted data frames:", count_all_retry_data_frames())
    print("Percentage of re-transmitted data frames", CLIENT, '(client) ---->', AP, '(AP):', count_retry_data_frames_from_to(CLIENT, AP))
    print("\nData frame bytes", CLIENT, '(client) ---->', AP, '(AP):', data_frame_bytes_from_to(CLIENT, AP), 'bytes')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--client', metavar='<client MAC address>',
                        help='The transmitting node', required=True)
    parser.add_argument('--ap', metavar='<AP MAC address>',
                        help='The receiving node', required=True)
    args = parser.parse_args()

    global FILE_NAME

    FILE_NAME = args.pcap
    AP = args.ap
    CLIENT = args.client

    
    #CLIENT = 'dc:a6:32:32:40:45'
    #AP = 'dc:a6:32:32:3f:fa'


    if not os.path.isfile(FILE_NAME):
        print('"{}" does not exist'.format(FILE_NAME), file=sys.stderr)
        sys.exit(-1)

    print("Starting processing of PCAP file", FILE_NAME, "\n")
    process_pcap(AP, CLIENT)
    sys.exit(0)
