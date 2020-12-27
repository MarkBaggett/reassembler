#!/usr/bin/python3

#This program will work in either Python2 or Python3
#The following code will reassemble fragmented packets using the BSD, BSD-Right, First, Last and Linux so that an analyst gets a better understanding of how an attack would affect each of his different hosts.
#This program was written by @MarkBaggett and is available for download at https://github.com/markbaggett/reassembler
#If you have questions about the script you can read the associated SANS Gold paper called "IP Fragment Reassembly with Scapy" by Mark Baggett

from scapy.all import *
import sys
if sys.version_info.major==2:
   from cStringIO import StringIO as BytesIO
   input = raw_input
else:
   from io import BytesIO


def clean_reassembled_packets(pkt_in, fix_checksum = True):
    pkt_in[IP].flags=0
    del pkt_in[IP].chksum
    del pkt_in[IP].len
    newpkt = Ether() / pkt_in[IP]
    if pkt_in.haslayer(Ether):
        newpkt[Ether].src = pkt_in[Ether].src
        newpkt[Ether].dst = pkt_in[Ether].dst
    if hasattr( newpkt[IP].payload.__class__, "chksum") and fix_checksum:
        del newpkt[IP].payload.chksum
    return newpkt


def rfc791(fragmentsin, fix_checksum=True):
    #Last to arrive temporaly wins
    buffer=BytesIO()
    for pkt in fragmentsin:
        if pkt[IP].frag == 0:
            first_fragment = pkt.copy()
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first_fragment[IP].payload = first_fragment[IP].payload.__class__(bytes(buffer.getvalue()))
    return clean_reassembled_packets(first_fragment, fix_checksum)

def first(fragmentsin, fix_checksum=True):
    #First to arrive temporaly wins
    buffer=BytesIO()
    for pkt in fragmentsin[::-1]:
        if pkt[IP].frag == 0:
            first_fragment = pkt.copy()
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first_fragment[IP].payload = first_fragment[IP].payload.__class__(bytes(buffer.getvalue()))
    return clean_reassembled_packets(first_fragment, fix_checksum)


def bsdright(fragmentsin, fix_checksum=True):
    #highest offset , Tie to last temporaly
    buffer=BytesIO()
    for pkt in sorted(fragmentsin, key= lambda x:x[IP].frag):
        if pkt[IP].frag == 0:
            first_fragment = pkt.copy()
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first_fragment[IP].payload = first_fragment[IP].payload.__class__(bytes(buffer.getvalue()))
    return clean_reassembled_packets(first_fragment, fix_checksum)

def bsd(fragmentsin, fix_checksum=True):
    #lowest offset, Tie to first
    buffer=BytesIO()
    for pkt in sorted(fragmentsin, key=lambda x:x[IP].frag)[::-1]:
        if pkt[IP].frag == 0:
            first_fragment = pkt.copy()
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first_fragment[IP].payload = first_fragment[IP].payload.__class__(bytes(buffer.getvalue()))
    return clean_reassembled_packets(first_fragment, fix_checksum)
 
def linux(fragmentsin, fix_checksum=True):
    #Lowest offset, Tie to last
    buffer=BytesIO()
    for pkt in sorted(fragmentsin, key= lambda x:x[IP].frag, reverse=True):
        if pkt[IP].frag == 0:
            first_fragment = pkt.copy()
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first_fragment[IP].payload = first_fragment[IP].payload.__class__(bytes(buffer.getvalue()))
    return clean_reassembled_packets(first_fragment, fix_checksum)

def other(fragmentsin, fix_checksum=True):
    #highest offset, Tie to first
    buffer=BytesIO()
    for pkt in sorted(fragmentsin, key= lambda x:x[IP].frag, reverse=True)[::-1]:
        if pkt[IP].frag == 0:
            first_fragment = pkt.copy()
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    first_fragment[IP].payload = first_fragment[IP].payload.__class__(bytes(buffer.getvalue()))
    return clean_reassembled_packets(first_fragment, fix_checksum)
    

def genjudyfrags():
    pkts=scapy.plist.PacketList()
    pkts.append(IP(flags="MF",frag=0)/ICMP()/("1"*24))
    pkts.append(IP(flags="MF",frag=5)/("2"*16))
    pkts.append(IP(flags="MF",frag=7)/("3"*24))
    pkts.append(IP(flags="MF",frag=2)/("4"*32))
    pkts.append(IP(flags="MF",frag=7)/("5"*24))
    pkts.append(IP(frag=10)/("6"*24))
    return pkts

def processfrags(fragmenttrain, fix_checksum = True, print_bytes=False):
    def print_frag(bytes_in):
        if print_bytes:
            print(bytes_in)
            return
        as_str = bytes_in
        try:
            as_str = bytes_in.decode()
        except:
            pass
        print(as_str)
        return      
    print("Reassembled using policy: First (Windows*, SUN, MacOS*, HPUX)")
    print_frag(first(fragmenttrain, fix_checksum)[Raw].load)
    print("\nReassembled using policy: Last/RFC791 (Cisco)")
    print_frag(rfc791(fragmenttrain, fix_checksum)[Raw].load)
    print("\nReassembled using policy: Linux (Linux prior to v5.8)")
    print_frag(linux(fragmenttrain, fix_checksum)[Raw].load)
    print("\nReassembled using policy: BSD (AIX, FreeBSD, HPUX, VMS)")
    print_frag(bsd(fragmenttrain, fix_checksum)[Raw].load)
    print("\nReassembled using policy: BSD-Right (HP Jet Direct)")
    print_frag(bsdright(fragmenttrain, fix_checksum)[Raw].load)
    print("\nReassembled using policy: Other (Some IoT Device somewhere)")
    print_frag(other(fragmenttrain, fix_checksum)[Raw].load)
    
def writefrags(fragmenttrain, file_prefix, fix_checksum=True): 
    ipid = str(fragmenttrain[0][IP].id)
    wrpcap(f"{file_prefix}-{ipid}-first.pcap", first(fragmenttrain, fix_checksum))
    wrpcap(f"{file_prefix}-{ipid}-rfc791.pcap", rfc791(fragmenttrain, fix_checksum))
    wrpcap(f"{file_prefix}-{ipid}-bsd.pcap", bsd(fragmenttrain, fix_checksum))
    wrpcap(f"{file_prefix}-{ipid}-bsdright.pcap", bsdright(fragmenttrain, fix_checksum))
    wrpcap(f"{file_prefix}-{ipid}-linux.pcap", linux(fragmenttrain, fix_checksum))
    wrpcap(f"{file_prefix}-{ipid}-other.pcap", other(fragmenttrain, fix_checksum))
    
    

