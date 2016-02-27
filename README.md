# Briefcap

This program analyzes .pcap packet capture files (which are usually
created by wireshark, tshark, or tcpdump), and prints a summary of
ethernet, IPv4, TCP, UDP, and ICMP contents therein.

# Usage

Usage: `./briefcap [options] [capture file]`

Options are:

  - `-h` to print a help message and exit.
  - `-v` to make the program run verbosely.

# References

  - http://www.tcpdump.org/linktypes.html
  - http://www.tcpdump.org/sniffex.c
  - http://wiki.wireshark.org/Development/LibpcapFileFormat
  - http://wiki.wireshark.org/SampleCaptures
  - http://en.wikipedia.org/wiki/Ethertype
