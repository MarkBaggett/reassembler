# reassembler
## A Python implementation of the various OS IPv4 packet fragment reassembly engines.

### One Packet in => Six Packets out

This module will reassemble fragmented packets using common used fragmentation reassembly techniques.  It then generates 6 pcap files. It also prints the payloads to the screen and shows you how each of the operating systems would see the packets after they reassemble them using their defragmentation engine.

This is a rewrite of the original released in 2012 to support Python3.
[Associated GIAC SANS Gold Paper](https://www.sans.org/reading-room/whitepapers/tools/ip-fragment-reassembly-scapy-33969)

---

### Are Overlapping fragments still an issue?

10-16-2020: [Don Williams](https://twitter.com/bashwrapper) and I did a survey of the major OSes to confirm the status of their reassembly engines. Here are the results:

 - [Linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c30f1fc041b74ecdb072dd44f858750414b8b19f) 
: The Linux OS's have begun silently ignoring overlapping IPv4 fragments. IPv6 rejects them by defalt.

 - [Windows](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV180022): The posted "Fix" requires that you turn off ALL fragment reassembly, not just overlaps. It is not enabled by default.  I have been unable to get any Windows OS to respond to overlaps since Vista.

 - Macintosh: Tested on 10-16-2020 and it was still reassembling overlapping fragments without complaint.
 
---

### Installing

```pip install reassembler```

or

```pip install git+https://github.com/markbaggett/reassembler```

---

### Running

After pip install the command 'reassembler' is added to your path.

```
$ reassembler ./sample_packets/final_frags.pcap 
```


or you can execute it as a python module

```
$ python -m reassembler
usage: reassembler [options] pcap_file

positional arguments:
  pcap                  Read the specified packet capture

optional arguments:
  -h, --help            show this help message and exit
  -d, --demo            Generate classic fragment test pattern and reassemble it.
  -n, --no-write        Suppress writing 5 files to disk with the payloads.
  -b, --bytes           Process Payloads as bytes and never as strings.
  -q, --quiet           Do not print payloads to screen.
  -p PREFIX, --prefix PREFIX
                        Specify the prefix for file names
  -c, --checksum        Do not recalculate transport layer protocol checksums.
```

To use the Policy identifier scanner requires root privilege and you must still put something in the pcap field even though it is not used (to be fixed later).  If you are using a python virtual environment then to use sudo you must provide the path to the python binary that is in the virtual environment.  For now, this is initiated by an arp ping and is limited to host on your local network. This limitation will be removed soon.


```
$ sudo /path/to/venv/bin/python -m reassembler -ip 192.168.1.1/24 ignorepcap
```

---

### As a Module

```
>>> import reassembler
>>> reassembler.rfc791(reassembler.genjudyfrags())
<Ether  type=IPv4 |<IP  flags= frag=0 proto=icmp |<ICMP  type=echo-request code=0 id=0x0 seq=0x0 |<Raw  load='111111114444444444444444444444444444444422222222555555555555555555555555666666666666666666666666' |>>>>
>>> reassembler.first(reassembler.genjudyfrags())
<Ether  type=IPv4 |<IP  flags= frag=0 proto=icmp |<ICMP  type=echo-request code=0 id=0x0 seq=0x0 |<Raw  load='111111111111111111111111444444442222222222222222333333333333333333333333666666666666666666666666' |>>>>
>>> reassembler.linux(reassembler.genjudyfrags())
<Ether  type=IPv4 |<IP  flags= frag=0 proto=icmp |<ICMP  type=echo-request code=0 id=0x0 seq=0x0 |<Raw  load='111111111111111111111111444444444444444422222222555555555555555555555555666666666666666666666666' |>>>>
>>> reassembler.scan_network("192.168.1.1")
Checking host 192.168.1.1:
  + 192.168.1.1 responded to a ping request! 
  + 192.168.1.1 is reassembling normal (non-overlapping) fragmented ping packets.
  + 192.168.1.1 is NOT responding to overlapping fragments ping packets.
  + Overlapping fragments ignored by 192.168.1.1
>>> reassembler.scan_network("192.168.1.1/24")
<output truncated>

```


---

![](reassembler.jpg)