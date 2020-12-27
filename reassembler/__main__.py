from reassembler import *
from scapy.all import *
import argparse
import os
import sys

   
def cli():
    parser=argparse.ArgumentParser(usage="reassembler [options] pcap_file")
    parser.add_argument('pcap',default="",help='Read the specified packet capture')
    parser.add_argument('-d','--demo',action='store_true', help='Generate classic fragment test pattern and reassemble it.')
    parser.add_argument('-n','--no-write',action='store_true', dest="nowrite", help='Suppress writing 5 files to disk with the payloads.')
    parser.add_argument('-b','--bytes',action='store_true',  help='Process Payloads as bytes and never as strings.')
    parser.add_argument('-q','--quiet',action='store_true',  help='Do not print payloads to screen.')  
    parser.add_argument('-p','--prefix',default='reassembled', help='Specify the prefix for file names')
    parser.add_argument('-c','--checksum',action="store_true", help='Do not recalculate transport layer protocol checksums.')
    

    if (len(sys.argv)==1):
        parser.print_help()
        sys.exit()

    options=parser.parse_args()

    if options.demo:
        processfrags(genjudyfrags())

    if not os.path.exists(options.pcap):
        print("Packet capture file not found.")
        sys.exit(2)

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
                processfrags(fragmenttrain, not options.checksum, options.bytes)
            if not options.nowrite:
                writefrags(fragmenttrain, options.prefix, not options.checksum)

cli()