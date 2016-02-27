# Briefcap

This program analyzes .pcap capture files, and prints a summary.

`briefcap` looks at a pcap-format capture file (usually created by
wireshark, tshark, tcpdump, etc.) and marvels at its contents, usually
by printing out a summary.  Briefcap is interested only in ethernet,
IPv4, TCP, UDP and ICMP.

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
