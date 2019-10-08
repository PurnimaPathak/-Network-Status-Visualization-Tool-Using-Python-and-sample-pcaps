{\rtf1\ansi\ansicpg1252\cocoartf1671\cocoasubrtf500
{\fonttbl\f0\fmodern\fcharset0 CourierNewPSMT;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;\red255\green255\blue255;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;\cssrgb\c100000\c100000\c100000;}
\margl1440\margr1440\vieww10800\viewh8400\viewkind0
\deftab720
\pard\pardeftab720\partightenfactor0

\f0\fs28 \cf2 \cb3 \expnd0\expndtw0\kerning0
# Name : Purnima Pathak\
# Purpose: Traffic Analyzer Tool- Network Security Final Project\
# Date : 05/01/2018\
\
from scapy.all import *\
import os\
import sys\
import dpkt\
import numpy as np\
import pandas as pd\
import matplotlib.pyplot as plt\
import argparse\
\
FIN = 0x01\
SYN = 0x02\
RST = 0x04\
PSH = 0x08\
ACK = 0x10\
URG = 0x20\
ECE = 0x40\
CWR = 0x80\
\
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'third_party', 'dpkt')\
if p not in sys.path:\
    sys.path.insert(0, p)\
\
from collections import defaultdict\
\
TLSV1_2_CLIENTS = 'TLSv1.2_clients'\
TLSV1_1_CLIENTS = 'TLSv1.1_clients'\
TLSV1_CLIENTS = 'TLSv1_clients'\
SSL_V1__CLIENTS = 'SSLv3_clients'\
TLS_HANDSHAKE = 22\
ICMP = "ICMP"\
HAND_SHAKE = "HandShake"\
UDP = "UDP"\
TCP = "TCP"\
\
ssl3_versions = \{\
    'SSL3': b'\\x03\\x00',\
    'TLS 1.0': b'\\x03\\x01',\
    'TLS 1.1': b'\\x03\\x02',\
    'TLS 1.2': b'\\x03\\x03'\
\}\
\
DEBUG = False\
\
\
def as_percent(a, b):\
    if a == 0:\
        return "0%"\
    if a > b:\
        assert ('invalid percentage')\
\
    val = float(a) / float(b)\
    return "%.2f%%" % (val * 100)\
\
\
def create_statistics(cap):\
    counters = defaultdict(int)\
    pkt_count = parse_pcap(cap, counters)\
    stats = [\
        \{\
            'name': 'All packets',\
            'value': str(pkt_count),\
        \},\
        \{\
            'name': 'SSL v3 Clients',\
            'value': as_percent(counters[SSL_V1__CLIENTS], pkt_count),\
        \},\
        \{\
            'name': 'TLS v1 Clients',\
            'value': as_percent(counters[TLSV1_CLIENTS], pkt_count),\
        \},\
        \{\
            'name': 'TLS v1.1 Clients',\
            'value': as_percent(counters[TLSV1_1_CLIENTS], pkt_count),\
        \},\
        \{\
            'name': 'TLS v1.2 Clients',\
            'value': as_percent(counters[TLSV1_2_CLIENTS], pkt_count),\
        \},\
        \{\
            'name': 'Handshake packets',\
            'value': as_percent(counters[HAND_SHAKE], pkt_count),\
        \},\
        \{\
            'name': 'Sent DNS Request',\
            'value': as_percent(counters["DNS"], pkt_count),\
        \},\
        \{\
            'name': 'UDP Packets',\
            'value': as_percent(counters[UDP], pkt_count),\
        \},\
        \{\
            'name': 'ICMP Packets',\
            'value': as_percent(counters[ICMP], pkt_count),\
        \}\
    ]\
    return stats\
\
\
def parse_pcap(cap, counters):\
    pkt_count = 0\
    for ts, buf in cap:\
        pkt_count += 1\
        eth = dpkt.ethernet.Ethernet(buf)\
        # print 'pkt: %d' % (pkt_count)\
        if not isinstance(eth.data, dpkt.ip.IP):\
            continue\
        ip = eth.data\
\
        if ip.p == dpkt.ip.IP_PROTO_TCP:\
            if ip.data.dport == 443 or ip.data.sport == 443:\
                try:\
                    if ip.data.data.find(ssl3_versions['SSL3']) == 1:\
                        counters[SSL_V1__CLIENTS] += 1\
                    elif ip.data.data.find(ssl3_versions['TLS 1.0']) == 1:\
                        counters[TLSV1_CLIENTS] += 1\
                    elif ip.data.data.find(ssl3_versions['TLS 1.1']) == 1:\
                        counters[TLSV1_1_CLIENTS] += 1\
                    elif ip.data.data.find(ssl3_versions['TLS 1.2']) == 1:\
                        counters[TLSV1_2_CLIENTS] += 1\
                    if ip.data.data[0] == TLS_HANDSHAKE:\
                        counters[HAND_SHAKE] += 1\
                except dpkt.dpkt.NeedData as e:\
                    continue\
                except dpkt.ssl.SSL3Exception as e:\
                    pass\
                except IndexError as e:\
                    continue\
            counters[TCP] += 1\
\
        if ip.p == dpkt.ip.IP_PROTO_UDP:\
            if ip.data.dport == 53 or ip.data.sport == 53:\
                counters["DNS"] += 1\
            counters[UDP] += 1\
\
        if ip.p == dpkt.ip.IP_PROTO_ICMP:\
            counters[ICMP] += 1\
    return pkt_count\
\
\
def main():\
    parser = argparse.ArgumentParser()\
    parser.add_argument("PcapFile")\
    args = parser.parse_args()\
    if args.PcapFile is None:\
        print("Please input the pcap file")\
        sys.exit()\
\
    file = args.PcapFile\
    # flagReader(file)\
\
    try:\
        with open(file, 'rb') as fp:\
            stats = create_statistics(dpkt.pcap.Reader(fp))\
    except:\
        print("File is not correct");\
        exit(1)\
\
    plot_graph(stats)\
\
    for stat in stats:\
        print("%s: %s" % (stat['name'], stat['value']))\
\
\
def plot_graph(stats):\
    left = [1, 2, 3, 4, 5, 6, 7, 8]\
    # height = [1 if float(stat["value"][:-1]) < 1 else int(float(stat["value"][:-1])) for stat in stats][1:]\
\
    height = [float(stat["value"][:-1]) for stat in stats][1:]\
    tick_label = [stat["name"] for stat in stats][1:]\
    # plotting a bar chart\
    plt.bar(left, height, tick_label=tick_label,\
            width=0.8, color=['red', 'green'])\
    plt.xlabel('x - axis')\
    plt.ylabel('y - axis')\
    # plt.xticks(np.arange(min(0), max(1) + 1, 1.0))\
\
    plt.title('Statistics about Packets with different protocols')\
    plt.show()\
\
\
# def flagReader(file):\
#     pkts = PcapReader(file)\
#     for p in pkts:\
#         F = p['TCP'].flags\
#\
#         if F & FIN:\
#             print('FIN flag activated')\
#         if F & SYN:\
#             print('SYN flag activated')\
#         if F & RST:\
#             print('RST flag activated')\
#         if F & PSH:\
#             print('PSH flag activated')\
#         if F & ACK:\
#             print('ACK flag activated')\
#         if F & URG:\
#             print('URG flag activated')\
#         if F & ECE:\
#             print('ECE flag activated')\
#         if F & CWR:\
#             print('CWR flag activated')\
\
\
if __name__ == "__main__":\
    main()}