# reaassembler
Scapy packet fragment reassembly engines.

This module will reassemble fragmented packets using common used fragmentation reassembly techniques.  It then generates 5 pcap files.  One for each of the different reassembly engines. It also prints the payloads to the screen.

This is a rewrite of the original released in 2012 to support Python3.

[Associated GIAC SANS Gold Paper](https://www.sans.org/reading-room/whitepapers/tools/ip-fragment-reassembly-scapy-33969)


```
$ python3 reassembler.py fragments.pcap 
Reading fragmented packets from disk.
Packet fragments found.  Collecting fragments now.
Reassemble packets between hosts 10.1.1.117 and 10.1.1.109? [Y/N]Y
Reassembled using policy: First (Windows, SUN, MacOS, HPUX)
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false

Reassembled using policy: Last/RFC791 (Cisco)
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false

Reassembled using policy: Linux (Umm.. Linux)
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false

Reassembled using policy: BSD (AIX, FreeBSD, HPUX, VMS)
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false


Reassembled using policy: BSD-Right (HP Jet Direct)
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false
```
