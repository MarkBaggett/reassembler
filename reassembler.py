#!/usr/bin/python3

#This program will work in either Python2 or Python3
#The following code will reassemble fragmented packets using the BSD, BSD-Right, First, Last and Linux so that an analyst gets a better understanding of how an attack would affect each of his different hosts.
#This program was written by @MarkBaggett and is available for download at https://github.com/markbaggett/reassembler
#If you have questions about the script you can read the associated SANS Gold paper called "IP Fragment Reassembly with Scapy" by Mark Baggett

from scapy.all import *
import six
if six.PY2:
   from cStringIO import StringIO as StringIO
   input = raw_input
else:
   from io import BytesIO as StringIO
import argparse
import os
import sys

def rfc791(fragmentsin):
    #Last to arrive temporaly wins
    buffer=StringIO()
    for pkt in fragmentsin:
        if pkt[IP].frag == 0:
            wrapper = pkt
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    wrapper[IP].payload = wrapper[IP].payload.__class__(bytes(buffer.getvalue()))
    del wrapper[IP].len
    wrapper[IP].flags=0
    del wrapper[IP].chksum
    return wrapper

def first(fragmentsin):
    #First to arrive temporaly wins
    buffer=StringIO()
    for pkt in fragmentsin[::-1]:
        if pkt[IP].frag == 0:
            wrapper = pkt
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    wrapper[IP].payload = wrapper[IP].payload.__class__(bytes(buffer.getvalue()))
    del wrapper[IP].len
    wrapper[IP].flags=0
    del wrapper[IP].chksum
    return wrapper


def bsdright(fragmentsin):
    #highest offset , Tie to last temporaly
    buffer=StringIO()
    for pkt in sorted(fragmentsin, key= lambda x:x[IP].frag, reverse=True):
        if pkt[IP].frag == 0:
            wrapper = pkt
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    wrapper[IP].payload = wrapper[IP].payload.__class__(bytes(buffer.getvalue()))
    del wrapper[IP].len
    wrapper[IP].flags=0
    del wrapper[IP].chksum
    return wrapper

def bsd(fragmentsin):
    #lowest offset, Tie to first
    buffer=StringIO()
    for pkt in sorted(fragmentsin, key=lambda x:x[IP].frag, reverse=True)[::-1]:
        if pkt[IP].frag == 0:
            wrapper = pkt
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    wrapper[IP].payload = wrapper[IP].payload.__class__(bytes(buffer.getvalue()))
    del wrapper[IP].len
    wrapper[IP].flags=0
    del wrapper[IP].chksum
    return wrapper
 
def linux(fragmentsin):
    #Lowest offset, Tie to last
    buffer=StringIO()
    for pkt in sorted(fragmentsin, key= lambda x:x[IP].frag):
        if pkt[IP].frag == 0:
            wrapper = pkt
        buffer.seek(pkt[IP].frag*8)
        buffer.write(bytes(pkt[IP].payload))
    wrapper[IP].payload = wrapper[IP].payload.__class__(bytes(buffer.getvalue()))
    del wrapper[IP].len
    wrapper[IP].flags=0
    del wrapper[IP].chksum
    return wrapper

#The other policy sorted(x, key = lambda y:y[1])[::-1]


def genjudyfrags():
    pkts=scapy.plist.PacketList()
    pkts.append(IP(flags="MF",frag=0)/("1"*24))
    pkts.append(IP(flags="MF",frag=4)/("2"*16))
    pkts.append(IP(flags="MF",frag=6)/("3"*24))
    pkts.append(IP(flags="MF",frag=1)/("4"*32))
    pkts.append(IP(flags="MF",frag=6)/("5"*24))
    pkts.append(IP(frag=9)/("6"*24))
    return pkts

def processfrags(fragmenttrain):
    def print_frag(bytes_in):
        if options.bytes:
            print(bytes_in)
            return
        as_str = bytes_in
        try:
            as_str = bytes_in.decode()
        except:
            pass
        print(as_str)
        return      
    print("Reassembled using policy: First (Windows, SUN, MacOS, HPUX)")
    print_frag(first(fragmenttrain)[Raw].load)
    print("\nReassembled using policy: Last/RFC791 (Cisco)")
    print_frag(rfc791(fragmenttrain)[Raw].load)
    print("\nReassembled using policy: Linux (Umm.. Linux)")
    print_frag(linux(fragmenttrain)[Raw].load)
    print("\nReassembled using policy: BSD (AIX, FreeBSD, HPUX, VMS)")
    print_frag(bsd(fragmenttrain)[Raw].load)
    print("\nReassembled using policy: BSD-Right (HP Jet Direct)")
    print_frag(bsdright(fragmenttrain)[Raw].load)
    
def writefrags(fragmenttrain): 
    wrpcap(options.prefix+"-first.pcap", first(fragmenttrain))
    wrpcap(options.prefix+"-rfc791.pcap", rfc791(fragmenttrain))
    wrpcap(options.prefix+"-bsd.pcap", bsd(fragmenttrain))
    wrpcap(options.prefix+"-bsdright.pcap", bsdright(fragmenttrain))
    wrpcap(options.prefix+"-linux.pcap", linux(fragmenttrain))
    
    
def main():
    print("Reading fragmented packets from disk.")
    packets=rdpcap(options.pcap)
    ippackets=[a for a in packets if a.haslayer("IP")]
    fragmentedpackets=[a for a in ippackets if a[IP].flags==1 or a[IP].frag > 0]
    
    if len(fragmentedpackets)==0:
        print("No fragments in packet capture.")
        sys.exit(2)

    uniqipids={}
    for a in fragmentedpackets:
         uniqipids[a[IP].id]='we are here'

    for ipid in list(uniqipids.keys()):
        print("Packet fragments found.  Collecting fragments now.")
        fragmenttrain = [ a for a in fragmentedpackets if a[IP].id == ipid ] 
        processit = input("Reassemble packets between hosts "+str(fragmenttrain[0][IP].src)+" and "+str(fragmenttrain[0][IP].dst)+"? [Y/N]")
        if str(processit).lower()=="y":
            if not options.quiet:
                processfrags(fragmenttrain)
            if not options.nowrite:
                writefrags(fragmenttrain)

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('pcap',default="",help='Read the specified packet capture')
    parser.add_argument('-d','--demo',action='store_true', help='Generate classic fragment test pattern and reassemble it.')
    parser.add_argument('-n','--no-write',action='store_true', dest="nowrite", help='Suppress writing 5 files to disk with the payloads.')
    parser.add_argument('-b','--bytes',action='store_true',  help='Process Payloads as bytes and never as strings.')
    parser.add_argument('-q','--quiet',action='store_true',  help='Do not print payloads to screen.')  
    parser.add_argument('-p','--prefix',default='reassembled', help='Specify the prefix for file names')

    if (len(sys.argv)==1):
        parser.print_help()
        sys.exit()

    options=parser.parse_args()

    if options.demo:
        processfrags(genjudyfrags())

    if not os.path.exists(options.pcap):
        print("Packet capture file not found.")
        sys.exit(2)

    main()
