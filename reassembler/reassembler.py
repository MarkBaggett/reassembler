#!/usr/bin/python3

#This program will work in either Python2 or Python3
#The following code will reassemble fragmented packets using the BSD, BSD-Right, First, Last and Linux so that an analyst gets a better understanding of how an attack wotmp affect each of his different hosts.
#This program was written by @MarkBaggett and is available for download at https://github.com/markbaggett/reassembler
#If you have questions about the script you can read the associated SANS Gtmp paper called "IP Fragment Reassembly with Scapy" by Mark Baggett

from scapy.all import *
import sys
import random
if sys.version_info.major==2:
   from cStringIO import StringIO as BytesIO
   input = raw_input
else:
   from io import BytesIO


def clean_reassembled_packets(pkt_in, fix_checksum = True):
    #This function fixes fields such as checksums,lengths and adds an ethernet frame tested on udp and icmp
    #Delete any fields we want recalculated
    pkt_in[IP].flags=0
    del pkt_in[IP].chksum
    embedded = pkt_in[IP].payload.__class__
    #scapy incorrectly sets len on UDP packets and adds a "Padding" layer.  Patch that here.
    if hasattr( pkt_in[IP].payload.__class__, "len"):
        tmp = embedded(bytes(pkt_in[IP].payload))
        if tmp.haslayer(Padding):
            pkt_in[IP].payload.len = pkt_in[IP].payload.len + len(tmp[Padding].load)
    if hasattr( pkt_in[IP].payload.__class__, "chksum") and fix_checksum:
        del pkt_in[IP].payload.chksum
    #Force recalc of checksums and other blank fields by turning things into bytes and back    
    newpkt = Ether() / IP(bytes(pkt_in[IP])) 
    newpkt[embedded] = embedded(bytes(pkt_in[IP].payload))
    if pkt_in.haslayer(Ether):
        newpkt[Ether].src = pkt_in[Ether].src
        newpkt[Ether].dst = pkt_in[Ether].dst
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


def normal_fragmented_ping(ipaddr):
    #Create a ping request with normal nonoverlapping fragments and see if it responds
    simple_fragment = scapy.plist.PacketList()
    simple_fragment.append(IP(dst=ipaddr, flags="MF",frag=0)/ICMP(type=8,code=0,chksum=20311)/("1"*24))
    simple_fragment.append(IP(dst=ipaddr, proto="icmp",frag=4)/("2"*24))
    res = sr1(simple_fragment, timeout=2, verbose=0)
    if not res:
        return False, f"{ipaddr} is NOT responding to normal fragments ping packets."
    elif res[0][ICMP].type==0:
        return True, f"{ipaddr} is reassembling normal (non-overlapping) fragmented ping packets."
    else:
        return False, f"{ipaddr} is NOT responding to normal fragments."


def overlap_fragmented_ping(ipaddr):
    #Create a ping request with overlapping fragments and see if it responds
    simple_fragment = scapy.plist.PacketList()
    simple_fragment.append(IP(dst=ipaddr, flags="MF",frag=0)/ICMP(type=8,code=0,chksum=0xafb7)/("X"*32))
    simple_fragment.append(IP(dst=ipaddr, proto="icmp",frag=4)/("X"*24))
    res = sr1(simple_fragment, timeout=2, verbose=0)
    if not res:
        return False, f"{ipaddr} is NOT responding to overlapping fragments ping packets."
    elif res[0][ICMP].type==0:
        return True, f"{ipaddr} is reassembling overlapping fragmented ping packets."
    else:
        return False, f"{ipaddr} is NOT responding to overlapping fragments."


def ping(ipaddr):
    #Try to ping a host
    res = sr1(IP(dst=ipaddr)/ICMP()/"ABCDEFG", timeout=2, verbose=0)
    if not res:
        return False, f"Can not ping {ipaddr}."
    elif res[0][ICMP].type==0:
        return True, f"{ipaddr} responded to a ping request! "
    else:
        return False, f"Can not ping {ipaddr}."      
    

def genjudyfrags(ipaddr = "127.0.0.1", policy='first'):
    #Given IP and desired fragmentation policy creates fragmented ICMP pattern and sets ICMP check sum to the specified policy
    chksums = {'first':22110, 'linux': 13886, 'bsd': 20054, 'bsdright':9774, 'rfc791': 7718, 'other':15942} 
    pkts=scapy.plist.PacketList()
    pkts.append(IP(dst=ipaddr, flags="MF",frag=0)/ICMP(type=8,code=0,chksum=chksums[policy])/("1"*24))
    pkts.append(IP(dst=ipaddr,flags="MF",proto="icmp",frag=5)/("2"*16))
    pkts.append(IP(dst=ipaddr,flags="MF",proto="icmp",frag=7)/("3"*24))
    pkts.append(IP(dst=ipaddr,flags="MF",proto="icmp",frag=2)/("4"*32))
    pkts.append(IP(dst=ipaddr,flags="MF",proto="icmp",frag=7)/("5"*24))
    pkts.append(IP(dst=ipaddr,frag=10,proto="icmp")/("6"*24))
    return pkts


def genoverlaps(ipaddr = "127.0.0.1"):
    #Given IP create packets that contain unique patters for different reassemblies but all have the same checksum
    pkts=scapy.plist.PacketList()
    ipid = random.randrange(1,65535)
    pkts.append(IP(dst=ipaddr, id=ipid,flags="MF",frag=0)/ICMP(type=8,code=0,chksum=30334)/("11223344"*3))
    pkts.append(IP(dst=ipaddr,id=ipid,flags="MF",proto="icmp",frag=5)/("22334411"*2))
    pkts.append(IP(dst=ipaddr,id=ipid,flags="MF",proto="icmp",frag=7)/("33441122"*3))
    pkts.append(IP(dst=ipaddr,id=ipid,flags="MF",proto="icmp",frag=2)/("44332211"*4))
    pkts.append(IP(dst=ipaddr,id=ipid,flags="MF",proto="icmp",frag=7)/("44112233"*3))
    pkts.append(IP(dst=ipaddr,id=ipid,frag=10,proto="icmp")/("44223311"*3))
    return pkts


#Testing when reassembly stopped on Windows.  This works on all modern windows tested Win7,8,10
#uses UDP so 'nc -nvv -l -u -p 10000' on the remote host and observe pattern
# def gensimple_nooverlap(ipaddr = "127.0.0.1"):
#     ipid = random.randrange(1,65535)
#     pkts=scapy.plist.PacketList()
#     pkts.append(IP(dst=ipaddr,id=ipid, flags="MF",frag=0)/UDP(sport=9000, dport=10000,chksum=15758)/("11223344"*2))
#     pkts.append(IP(dst=ipaddr,id=ipid, proto="udp",frag=4)/("44112233"))
#     pkts.append(IP(dst=ipaddr,id=ipid, flags="MF", proto="udp",frag=3)/("44332211"))
#     return pkts
#This does NOT work on Win7,8,10 but dooes on WINXP
# def gensimple_withoverlap(ipaddr = "127.0.0.1"):
#     ipid = random.randrange(1,65535)
#     pkts=scapy.plist.PacketList()
#     pkts.append(IP(dst=ipaddr,id=ipid, flags="MF",frag=0)/UDP(sport=9000, dport=10000,chksum=15758)/("11223344"*2))
#     pkts.append(IP(dst=ipaddr,id=ipid, proto="udp",frag=4)/("44112233"))
#     pkts.append(IP(dst=ipaddr,id=ipid, flags="MF", proto="udp",frag=3)/("44332211"*2))
#     return pkts


def fix_and_send(pkts, policy):
    #pkts is overlapping fragments and policy is one of the reassembly functions
    #Reassembles the packets to see what the checksum and len shoud be then sets them then send the packet
    #Returns what it sent and what was returned.
    reassembled =  policy(pkts,True)
    if hasattr( pkts[0][IP].payload.__class__, "chksum"):
        pkts[0][IP].payload.chksum = reassembled[IP].payload.chksum
    if hasattr( pkts[0][IP].payload.__class__, "len"):
        pkts[0][IP].payload.len = reassembled[IP].payload.len
    ans = sr1(pkts, timeout=3)
    return pkts, ans

def match_payload(fragmented_pkts, icmp_reply):
    if first(fragmented_pkts)[Raw].load == icmp_reply[Raw].load:
        policy = "FIRST"
    elif bsd(fragmented_pkts)[Raw].load == icmp_reply[Raw].load:
        policy = "BSD"
    elif bsdright(fragmented_pkts)[Raw].load == icmp_reply[Raw].load:
        policy = "BSDRIGHT"
    elif linux(fragmented_pkts)[Raw].load == icmp_reply[Raw].load:
        policy = "Linux"
    elif rfc791(fragmented_pkts)[Raw].load == icmp_reply[Raw].load:
        policy = "RFC791"
    elif other(fragmented_pkts)[Raw].load == icmp_reply[Raw].load:
        policy = "OTHER"
    else:
        policy = f"No Match for {icmp_reply[Raw].load}"
    return policy


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


def scan_host(ipaddr):
    print(f"Checking host {ipaddr}:")
    #Lets see if we can ping it first.
    result, msg = ping(ipaddr)
    print(f"  + {msg}")
    if not result:
        return
    #Now try a fragmented ping
    result,msg = normal_fragmented_ping(ipaddr)
    print(f"  + {msg}")
    if not result:
        return
    #Now try an overlapping fragmented ping
    result,msg = overlap_fragmented_ping(ipaddr)
    print(f"  + {msg}")
    #Last send overlap pattern and identify which policy
    pkts = genoverlaps(ipaddr)
    result = sr1(pkts, timeout=2, verbose=0)
    if result:
        print(f"  + {ipaddr} responds with reassembly {match_payload(pkts, result)}")
    else:
        print(f"  + Overlapping fragments ignored by {ipaddr}")


def scan_network2(mask):
    #Identifies policy by seeing which chksum causes the remote host to respond
    #takes longer than sending 1 packet an looking at the pattern because we send 6 packets and timeout on no response
    ans,unans = arping(mask, verbose=0)
    for sent,recv in ans:
        ipaddr = recv.psrc
        policy_identified = False
        for policy in ['first', 'linux', 'bsd','bsdright','rfc791','other']:
            res = sr1(genjudyfrags(ipaddr,policy), timeout=2, verbose=0)
            if not res:
                continue
            elif res[0][ICMP].type==0:
                print(f"{ipaddr} is using fragment reassembly policy {policy}")
                policy_identified = True
        if not policy_identified:
            print(f"{ipaddr} did not respond to any of the 6 standard overlapping fragments policies.")


#Random test
#scan_network("net/24")
#scan_network2("net/24")
#x = gensimple_withoverlap("ip")
#res = fix_and_send(x, first)
#print(res)  
    

