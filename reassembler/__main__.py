from reassembler import *
from scapy.all import *
import argparse
import os
import sys
import ipaddress
import socket


def process_scan_args(args):
    #Check for host name instead of IPs
    target = args.target
    if not target.replace(".","").replace(r"/","").isdigit():
        hostname = target.split(r"/")[0]
        ip = socket.gethostbyname(hostname)
        target = target.replace(hostname, ip)
    #Expand target specifier into network range.
    try:
        tgt_list = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print(f"{target} doens't look like a valid IP Address or network range.")
        print("A single IP address is in the form '192.168.1.1'.")
        print("A network range uses CIDR notation in is the form '192.168.0.0/16'.")
        print("I'll do my best to resolve hostnames for you so target.tst/24 might work.")
        exit(1)
    else:
        #Scan em
        for ipaddr in tgt_list:
            reassembler.scan_host(str(ipaddr))
    exit()

def process_assemble_args(options):
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
    exit()

def process_main(args):
    print('The first argument must by either "scan" or "assemble".')
    print("Try 'reassembler assemble -h' for help assembling fragmented packets. ")
    print("Try 'reassembler scan -h' for help. with the scanning host to identify their reassembly policy.")
    exit()

   
def cli():
    parser=argparse.ArgumentParser(usage="Try 'reassembler scan -h' or 'reassembler assemble -h' for help.\n\n")
    subparser = parser.add_subparsers()
    assemble = subparser.add_parser("assemble")
    assemble.add_argument('pcap',default="",help='Read the specified packet capture')
    assemble.add_argument('-d','--demo',action='store_true', help='Generate classic fragment test pattern and reassemble it.')
    assemble.add_argument('-n','--no-write',action='store_true', dest="nowrite", help='Suppress writing 5 files to disk with the payloads.')
    assemble.add_argument('-b','--bytes',action='store_true',  help='Process Payloads as bytes and never as strings.')
    assemble.add_argument('-q','--quiet',action='store_true',  help='Do not print payloads to screen.')  
    assemble.add_argument('-p','--prefix',default='reassembled', help='Specify the prefix for file names')
    assemble.add_argument('-c','--checksum',action="store_true", help='Do not recalculate transport layer protocol checksums.')
    assemble.set_defaults(func=process_assemble_args)
    scan = subparser.add_parser("scan")
    scan.add_argument("target", help="Identify Policy used by specified IP Address or Network Range")
    scan.set_defaults(func=process_scan_args)
    parser.set_defaults(func = process_main )

    args=parser.parse_args()
    args.func(args)



cli()