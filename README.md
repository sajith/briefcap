
# briefcap

This program analyzes .pcap capture files.

# Usage

Usage: ./briefcap [options] [capture file]
Options are:
   -h  Print this help message and exit.
   -v  Run verbosely.

"briefcap" looks at a pcap-format capture file (usually created by
wireshark, tshark, tcpdump, etc.) and marvels at its contents, usually
by printing out a summary of the said contents.  By design briefcap is
interested only in ethernet, IPv4, TCP, UDP and ICMP.  Everything else
is summarily rejected; sometimes a look of scorn is given.

"briefcap" is a convenient shell script wrapper to invoke the actual
binary, "briefcap.exe", and pipe the results throgh "less."

# References

  - http://www.tcpdump.org/linktypes.html
  - http://www.tcpdump.org/sniffex.c  
  - http://wiki.wireshark.org/Development/LibpcapFileFormat
  - http://wiki.wireshark.org/SampleCaptures
  - http://en.wikipedia.org/wiki/Ethertype

