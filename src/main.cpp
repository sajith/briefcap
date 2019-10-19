/*
 * Briefcap - analyze .pcap capture files.
 *
 * Copyright (C) 2012, 2016, 2019 Sajith Sasidharan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <numeric>
#include <utility>
#include <iostream>
#include <sstream>
#include <iomanip>

#include <unistd.h>
#include <sys/time.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>
#include <pcap/bpf.h>

using namespace std;

// ---------------------------------------------------------------------
// begin counters

static int                 g_n_packets    = 0;
static int                 g_n_badpackets = 0;
static vector<timeval>     g_time_stamps;
static vector<int>         g_pkt_sizes;

// Physical/Medium access things
static map<string, int>    g_eth_srcs;
static map<string, int>    g_eth_dsts;
static map<u_int16_t, int> g_eth_nwproto;

// Network layer things
static map<string, int>    g_ip_srcs;
static map<string, int>    g_ip_dsts;
static map<u_int8_t, int>  g_tr_proto;
static map<u_int32_t, int> g_ip_ttls;
static map<string, string> g_arp;

// Transport layer things
static map<u_int16_t, int> g_tcp_src_ports;
static map<u_int16_t, int> g_tcp_dst_ports;
static map<string, int>    g_tcp_flags;
static map<string, int>    g_tcp_options;
static map<u_int16_t, int> g_udp_src_ports;
static map<u_int16_t, int> g_udp_dst_ports;

// ICMP things
static map<string, int>    g_icmp_srcs;
static map<string, int>    g_icmp_dsts;
// promoting u_int8_t -> u_int32_t for display
static map<u_int32_t, int> g_icmp_types;
static map<u_int32_t, int> g_icmp_codes;
static map<string, int>    g_icmp_responses;

// end counters
// ---------------------------------------------------------------------

static int g_verbose_flag = 0;

inline bool is_verbose(void)
{
    return (g_verbose_flag != 0);
}

#define verbose(format,...) do {                                \
        if (is_verbose() == 1) {                                \
            char str[BUFSIZ];                                   \
            snprintf (str, BUFSIZ, format "\n", ##__VA_ARGS__); \
            cerr << str;                                        \
        }                                                       \
    } while (0);

// ---------------------------------------------------------------------

// given an ethernet address, return colon-separated string format
string eth2a(const u_int8_t eth[ETH_ALEN])
{
    if (eth == nullptr)
    {
        cerr << "bad argument!\n";
        return "";
    }

    char str[20];
    snprintf(str, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);

    return string(str);
}

// given an IP address, return
string ip2a(const u_int32_t *ip)
{
    if (ip == nullptr)
    {
        cerr << "bad argument!\n";
        return "";
    }

    char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, ip, str, INET_ADDRSTRLEN);

    return string(str);
}

// For certain captured items, we maintain a table that maps unique
// elements to their count.  Given such a map, this method increments
// the counter or creates a table entry with the count of 1.
template <class T, class V>
void update_counter (map<T, V> &m, const T &item)
{
    auto it = m.find(item);

    if (it == m.end())
    {
        m.insert(make_pair(item, 1));
    }
    else
    {
        it->second++;
    }
}

// For certain other items, we just maintain key-value pair of unique
// items.  For example, pairs of MAC addresses and IP addresses.
template <class T, class V>
void update_table(map<T, V> &m, const T &key, const V &val)
{
    m.insert(make_pair(key, val));
}

// update ethernet counters
void update_ether(const ethhdr *eth)
{
    if (eth == nullptr)
    {
        cerr << "bad argument!\n";
        return;
    }

    verbose("source eth: %s", eth2a(eth->h_source).c_str());
    verbose("dest eth: %s", eth2a(eth->h_dest).c_str());
    verbose("eth_proto=0x%04x", eth->h_proto);

    update_counter(g_eth_srcs, eth2a(eth->h_source));
    update_counter(g_eth_dsts, eth2a(eth->h_dest));
    update_counter(g_eth_nwproto, eth->h_proto);
}

// update IP counters
void update_ip(const ip *iph)
{
    // We have to deal with just IPv4 addresses here, and not IPv6
    // addresses.
    update_counter(g_ip_srcs, ip2a(&iph->ip_src.s_addr));
    update_counter(g_ip_dsts, ip2a(&iph->ip_dst.s_addr));

    update_counter(g_tr_proto, iph->ip_p);
    update_counter(g_ip_ttls, u_int32_t(iph->ip_ttl));

    verbose("update_ip post sz: %lu", g_ip_srcs.size());
}

// update TCP flags
void update_tcp_flags(const tcphdr *tcph)
{
    string flags;

    if (tcph->urg)
    {
        flags += "URG ";
    }

    if (tcph->ack)
    {
        flags += "ACK ";
    }

    if (tcph->psh)
    {
        flags += "PSH ";
    }

    if (tcph->rst)
    {
        flags += "RST ";
    }

    if (tcph->syn)
    {
        flags += "SYN ";
    }

    if (tcph->fin)
    {
        flags += "FIN ";
    }

    update_counter(g_tcp_flags, flags);
}

// Update TCP options.
void update_tcp_options(const tcphdr *tcph)
{
    if (tcph->doff == 5)
    {
        verbose("no options present");
        return;
    }

    // TCP header size is 20.
    u_int32_t  opsz = (tcph->doff - 5) * 4;
    u_int32_t  opln = 0;
    auto      *opts = reinterpret_cast<const u_int8_t *>(tcph + 20);

    bool nop_seen = false;

    for (;opsz > 0; opsz -= opln, opts += opln)
    {
        u_int32_t opt = opts[0];

        if (opt == TCPOPT_EOL)
        {
            return;
        }
        else if (opt == TCPOPT_NOP)
        {
            opln = 1;
        }
        else
        {
            if (opsz < 2)
            {
                return;
            }
            opln = opts[1];
            if (opln < 2 or opln > opsz)
            {
                return;
            }
        }

        if (opt == TCPOPT_NOP)
        {
            // HACK, because this is specific to NOP.  But NOP is the
            // only option that can reappear in a legitimate TCP
            // header, right?
            if (nop_seen == true)
            {
                continue;
            }
            update_counter(g_tcp_options,
                           string("0x01 (NOP)"));
            nop_seen = true;
        }
        else if (opt == TCPOPT_MAXSEG)
        {
            update_counter(g_tcp_options,
                           string("0x02 (MAXSEG)"));
        }
        else if (opt == TCPOPT_WINDOW)
        {
            update_counter(g_tcp_options,
                           string("0x03 (WINDOW)"));
        }
        else if (opt == TCPOPT_SACK_PERMITTED)
        {
            update_counter(g_tcp_options,
                           string("0x04 (SACK_PERMITTED)"));
        }
        else if (opt == TCPOPT_SACK)
        {
            update_counter(g_tcp_options,
                           string("0x05 (SACK)"));
        }
        else if (opt == TCPOPT_TIMESTAMP)
        {
            update_counter(g_tcp_options,
                           string("0x08 (TIMESTAMP)"));
        }
        else
        {
            // The above options have a name in <tcp.h>,
            // but what about the others? We just print
            // the option kind in hex.
            stringstream ss;
            ss.setf(ios::hex, ios::basefield);
            ss.setf(ios::showbase);

            ss << hex << opt;

            update_counter(g_tcp_options, ss.str());
        }
    }
}

// update TCP counters.
void update_tcp(const tcphdr *tcph)
{
    if (tcph == nullptr)
    {
        cerr << "bad argument!\n";
        return;
    }

    if (tcph->doff < 5)
    {
        cerr << "malformed TCP packet! (doff:"
             << int(tcph->doff) << ")\n";
        return;
    }

    update_counter(g_tcp_src_ports, ntohs(tcph->source));
    update_counter(g_tcp_dst_ports, ntohs(tcph->dest));

    update_tcp_flags(tcph);
    update_tcp_options(tcph);
}

// update UDP counters.
void update_udp(const udphdr *udph)
{
    if (udph == nullptr)
    {
        cerr << "bad argument!\n";
        return;
    }

    update_counter(g_udp_src_ports, ntohs(udph->source));
    update_counter(g_udp_dst_ports, ntohs(udph->dest));
}

void update_icmp_unreach(u_int8_t code)
{
    stringstream ss;

    switch (code)
    {
    case ICMP_UNREACH_NET:
        ss << "UNREACH_NET";
        break;
    case ICMP_UNREACH_HOST:
        ss << "UNREACH_HOST";
        break;
    case ICMP_UNREACH_PROTOCOL:
        ss << "UNREACH_PROTOCOL";
        break;
    case ICMP_UNREACH_PORT:
        ss << "UNREACH_PORT";
        break;
    case ICMP_UNREACH_NEEDFRAG:
        ss << "UNREACH_NEEDFRAG";
        break;
    case ICMP_UNREACH_SRCFAIL:
        ss << "UNREACH_SRCFAIL";
        break;
    case ICMP_UNREACH_NET_UNKNOWN:
        ss << "UNREACH_NET_UNKNOWN";
        break;
    case ICMP_UNREACH_HOST_UNKNOWN:
        ss << "UNREACH_HOST_UNKNOWN";
        break;
    case ICMP_UNREACH_ISOLATED:
        ss << "UNREACH_ISOLATED";
        break;
    case ICMP_UNREACH_NET_PROHIB:
        ss << "UNREACH_NET_PROHIB";
        break;
    case ICMP_UNREACH_HOST_PROHIB:
        ss << "UNREACH_HOST_PROHIB";
        break;
    case ICMP_UNREACH_TOSNET:
        ss << "UNREACH_TOSNET";
        break;
    case ICMP_UNREACH_TOSHOST:
        ss << "UNREACH_TOSHOST";
        break;
    case ICMP_UNREACH_FILTER_PROHIB:
        ss << "UNREACH_FILTER_PROHIB";
        break;
    case ICMP_UNREACH_HOST_PRECEDENCE:
        ss << "UNREACH_HOST_PRECEDENCE";
        break;
    case ICMP_UNREACH_PRECEDENCE_CUTOFF:
        ss << "UNREACH_PRECEDENCE_CUTOFF";
        break;
    default:
        ss << "UNREACH (code:" << int(code) << ")";
        break;
    }

    update_counter(g_icmp_responses, ss.str());
}

void update_icmp_redirect(u_int8_t code)
{
    stringstream ss;

    switch (code)
    {
    case ICMP_REDIRECT_NET:
        ss << "REDIRECT_NET";
        break;
    case ICMP_REDIRECT_HOST:
        ss << "REDIRECT_HOST";
        break;
    case ICMP_REDIRECT_TOSNET:
        ss << "REDIRECT_TOSNET";
        break;
    case ICMP_REDIRECT_TOSHOST:
        ss << "REDIRECT_TOSHOST";
        break;
    default:
        ss << "REDIRECT (code:" << int(code) << ")";
        break;
    }

    update_counter(g_icmp_responses, ss.str());
}

void update_icmp_timxceed(u_int8_t code)
{
    stringstream ss;

    switch (code)
    {
    case ICMP_TIMXCEED_INTRANS:
        ss << "TIMXCEED_INTRANS";
        break;
    case ICMP_TIMXCEED_REASS:
        ss << "TIMXCEED_REASS";
        break;
    default:
        ss << "TIMXCEED (code:" << int(code) << ")";
        break;
    }

    update_counter(g_icmp_responses, ss.str());
}

void update_icmp_paramprob(u_int8_t code)
{
    stringstream ss;

    switch (code)
    {
    case ICMP_PARAMPROB_OPTABSENT:
        ss << "PARAMPROB_OPTABSENT";
        break;
    default:
        ss << "PARAMPROB (code:" << int(code) << ")";
        break;
    }

    update_counter(g_icmp_responses, ss.str());
}

// update ICMP counters
void update_icmp(const icmphdr *icmph, const u_char *bytes)
{
    if (icmph == nullptr)
    {
        cerr << "bad argument!\n";
        return;
    }

    auto iph = reinterpret_cast<const ip *>(bytes + ETH_HLEN);

    update_counter(g_icmp_srcs, ip2a(&iph->ip_src.s_addr));
    update_counter(g_icmp_dsts, ip2a(&iph->ip_dst.s_addr));

    update_counter(g_icmp_types, u_int32_t(icmph->type));
    update_counter(g_icmp_codes, u_int32_t(icmph->code));

    switch (icmph->type)
    {
    case ICMP_UNREACH:
        update_icmp_unreach(icmph->code);
        break;
    case ICMP_REDIRECT:
        update_icmp_redirect(icmph->code);
        break;
    case ICMP_TIMXCEED:
        update_icmp_timxceed(icmph->code);
        break;
    case ICMP_PARAMPROB:
        update_icmp_paramprob(icmph->code);
        break;
    default:
        // ignore?
        break;
    }
}

// Given some transport bytes, parse it!
void parse_tr(u_int8_t ip_p, const u_char *bytes)
{
    // skip null checks here since they've already been passed in
    // parse_ip()
    auto   iph  = reinterpret_cast<const ip *>(bytes + ETH_HLEN);
    size_t iphl = iph->ip_hl * 4;

    const u_char *trpkt = bytes + ETH_HLEN + iphl;

    if (trpkt == nullptr)
    {
        cerr << "bad transport header!\n";
        return;
    }

    switch (ip_p)
    {
    case IPPROTO_TCP:
        update_tcp(reinterpret_cast<const tcphdr *>(trpkt));
        break;

    case IPPROTO_UDP:
        update_udp(reinterpret_cast<const udphdr *>(trpkt));
        break;

    case IPPROTO_ICMP:
        update_icmp(reinterpret_cast<const icmphdr *>(trpkt), bytes);
        break;

    default:
        verbose("unhandled protocol (ip_p=%d)", ip_p);
        break;
    }
}

// Given an IP header, parse it!
void parse_ip(const u_char *bytes)
{
    if (bytes == nullptr)
    {
        cerr << "bad argument!\n";
        return;
    }

    auto iph  = reinterpret_cast<const ip *>(bytes + ETH_HLEN);

    if (iph == nullptr)
    {
        cerr << "bad IP header!\n";
        return;
    }

    if (iph->ip_v != IPVERSION)
    {
        cerr << "not an IPv4 packet (v=" << iph->ip_v << "); "
            "skipping.\n";
        return;
    }

    size_t iphl = iph->ip_hl * 4;

    if (iphl < 20)
    {
        cerr << "iphl < 20 (iphl=" << iphl << "); skipping.\n";
        return;
    }

    verbose("iphl=%lu bytes\n", iphl);

    update_ip(iph);

    parse_tr(iph->ip_p, bytes);
}

// here we assume we always deal with ethernet ARP packets and make
// our own header.
struct eth_arphdr {
    u_int16_t ar_hrd;       // format of hardware address
    u_int16_t ar_pro;       // format of protocol address
    u_int8_t  ar_hln;       // length of hardware address
    u_int8_t  ar_pln;       // length of protocol address
    u_int16_t ar_op;        // ARP opcode (command)

    u_int8_t  ar_sha[ETH_ALEN]; // sender hardware address
    u_int8_t  ar_sip[4];        // sender IP address
    u_int8_t  ar_tha[ETH_ALEN]; // target hardware address
    u_int8_t  ar_tip[4];        // target IP address
};

// count ARP header contents
void parse_arp(const u_char *bytes)
{
    auto arph = reinterpret_cast<const eth_arphdr *>(bytes + ETH_HLEN);

    if (arph == nullptr)
    {
        cerr << "bad argument!\n";
        return;
    }

    verbose("arp hrd: %d", int(arph->ar_hrd));
    verbose("arp pro: %d", int(arph->ar_pro));
    verbose("arp hln: %d", int(arph->ar_hln));
    verbose("arp pln: %d", int(arph->ar_pln));
    verbose("arp op : %d", int(arph->ar_op));

    if (arph->ar_hln != ETH_ALEN and arph->ar_pln != 4)
    {
        cerr << "ARP packet is not ethernet/IP "
             << "(hrd:" << arph->ar_hrd
             << " pro:" << arph->ar_pro
             << " hln:" << arph->ar_hln
             << " pln:" << arph->ar_pln
             << " op:" << arph->ar_op
             << "\n";
        return;
    }

    verbose("arp sha: %s", eth2a(arph->ar_sha).c_str());
    verbose("arp sip: %s", ip2a((u_int32_t *) arph->ar_sip).c_str());
    verbose("arp tha: %s", eth2a(arph->ar_tha).c_str());
    verbose("arp tip: %s", ip2a((u_int32_t *) arph->ar_tip).c_str());

    update_table<string, string>(g_arp,
                                 eth2a(arph->ar_sha),
                                 ip2a((u_int32_t *) arph->ar_sip));
}

// callback for pcap_loop(), wherein we counts and counts and...
void pcap_callback(u_char            *user,
                   const pcap_pkthdr *h,
                   const u_char      *bytes)
{
    if (user == nullptr or h == nullptr or bytes == nullptr)
    {
        cerr << "bad args: user: " << user
             << ", h:" << h << ", bytes:" << bytes <<"\n";
        return;
    }

    g_n_packets++;

    if (h->caplen != h->len)
    {
        cerr << "(caplen:" << h->caplen
             << ") != (len:" << h->len << "); skipping.\n";
        g_n_badpackets++;
        return;
    }

    g_time_stamps.push_back(move(h->ts));

    auto eth = reinterpret_cast<const ethhdr *>(bytes);

    update_ether(eth);

    switch (htons(eth->h_proto))
    {
    case ETH_P_IP:
        parse_ip(bytes);
        break;
    case ETH_P_ARP:
        parse_arp(bytes);
        break;
    default:
        verbose("Unhandled eth proto 0x%04x", htons(eth->h_proto));
        break;
    }

    g_pkt_sizes.push_back(h->len);
}

// Check capture file format.
bool pcap_check_header(const char *infile)
{
    FILE *fp = fopen(infile, "r");

    if (!fp)
    {
        cerr << "can't open " << infile << "\n";
        return false;
    }

    pcap_file_header hdr;

    if (fread(&hdr, sizeof(pcap_file_header), 1, fp) != 1) {
        cerr << "error reading header!\n";
        return false;
    }

    if (is_verbose())
    {
        cout << "magic         : " << hdr.magic << "\n"
             << "version major : " << int(hdr.version_major) << "\n"
             << "version minor : " << int(hdr.version_minor) << "\n"
             << "snaplen       : " << int(hdr.snaplen) << "\n"
             << "linktype      : " << int(hdr.linktype) << "\n";
    }

    fclose(fp);

    return true;
}

// poor man's fancy formatting
void show_header(const char *name)
{
    cout << "\n\n"
         << "==================================================\n"
         << "\t" << name << "\n"
         << "==================================================\n";
}

// more of poor man's fancy formatting
void show_sub_header(const char *name)
{
    cout << "\n"
         << "--------------------------------------------------\n"
         << name << "\n"
         << "--------------------------------------------------\n";
}

// time stamp compare "functor", for std::sort()
constexpr bool cmp_ts(const timeval& tv1, const timeval& tv2)
{
    return timercmp(&tv1, &tv2, <);
}

// Given a struct timeval, return its calendar date string.
string ts2local(const timeval &tv)
{
    char tmbuf[64], resbuf[64];

    struct tm *ltm   = localtime(&tv.tv_sec);

    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", ltm);
    snprintf(resbuf, sizeof resbuf, "%s.%06lu", tmbuf, tv.tv_usec);

    return string(resbuf);
}

// Given a timeval, return its "hh:mm:ss.millisec" string.
string ts2a(const timeval &tv)
{
    tm *t = gmtime(&tv.tv_sec);

    char str[200];
    strftime(str, sizeof(str), "%H:%M:%S", t);

    stringstream ss;
    ss << str << "." << tv.tv_usec;

    return ss.str();
}

// show the summary header
void show_summary(void)
{
    show_header("Summary");

    sort(g_pkt_sizes.begin(), g_pkt_sizes.end());

    sort(g_time_stamps.begin(), g_time_stamps.end(), cmp_ts);

    timeval *start = &g_time_stamps[0];
    timeval *end   = &g_time_stamps[g_time_stamps.size() - 1];
    timeval diff;
    timersub(end, start, &diff);

    cout << "Start date       : " << ts2local(g_time_stamps [0]) << "\n"
         << "Duration         : " << ts2a(diff) << "\n";

    size_t smallest = g_pkt_sizes[0];
    size_t largest  = g_pkt_sizes[g_pkt_sizes.size() - 1];

    long sum = accumulate(g_pkt_sizes.begin(), g_pkt_sizes.end(), 0);

    double average  = double(sum) / g_pkt_sizes.size();

    cout << "# packets        : " << g_n_packets << "\n";
    cout << "# broken packets : " << g_n_badpackets << "\n";
    cout << "smallest         : " << smallest << " bytes\n";
    cout << "largest          : " << largest << " bytes\n";
    cout << "average          : "
         << setprecision(6) << average << " bytes\n";
}

// honey badger's sum of values in a <key,val> collection.
template<class U>
u_int32_t sum_values(const map<U,int> &m)
{
    u_int32_t sum = 0;

    for (auto const &it : m)
    {
        sum += it.second;
    }

    return sum;
}

// honey badger's percentage calculation, for a <key,val> collection.
template<class U, class V>
void show_percentage(const char *name, const map<U,V> &m,
                     bool usetotal = false)
{
    show_sub_header(name);

    if (m.size() == 0)
    {
        cout << "(None found.)\n";
        return;
    }

    for (auto const &it : m)
    {
        const U   &s = it.first;
        const V   &n = it.second;
        u_int32_t  t = 1;
        double     p = 0;

        if (usetotal)
        {
            t = g_n_packets;
        }
        else
        {
            t = sum_values(m);
        }

        if (t != 0)
        {
            p = double(n) * 100 / t;
        }
        else
        {
            p = 0; // not a very good approximation; but
            // hopefully we should never hit this!
        }

        cout << setw(25) << setfill(' ') << s
             << setw(5)  << n
             << setw(10) << p << " %\n";
    }
}

// honey badger displays IP protocol statistics
void show_ip_proto_stats(void)
{
    show_sub_header("Network layer protocols");

    if (g_eth_nwproto.size() == 0)
    {
        cout << "(None found)\n";
        return;
    }

    for (auto const &it : g_eth_nwproto) {
        const u_int16_t x = ntohs(it.first);
        const int       n = it.second;
        const double    p = double(n) * 100 / g_n_packets;

        string type;

        if (x == ETH_P_IP)
        {
            type = "IP";
        }
        else if (x == ETH_P_ARP)
        {
            type = "ARP";
        }
        else if (x > 0x0008)
        {
            // to handle ethertype:
            // http://en.wikipedia.org/wiki/Ethertype
            // Since h_proto is now in host byte order, we
            // compare it against 0x0008 and not 0x0800.
            stringstream ss;
            ss << "length = ";
            ss.setf(ios::hex, ios::basefield);
            ss.setf(ios::showbase);
            ss << hex << x;
            type = ss.str();
        }
        else
        {
            stringstream ss;
            ss.setf(ios::hex, ios::basefield);
            ss.setf(ios::showbase);

            ss << hex << x;

            type = ss.str();
        }

        cout << setw(25) << setfill(' ') << type
             << setw(5) << n
             << setw(10) << setprecision(5) << p << " %\n";
    }
}

// show unique parties involved in ARP dialogues.
void show_arp_parties(void)
{
    show_sub_header("Unique ARP participants");

    if (g_arp.size() == 0)
    {
        cout << "(None found.)\n";
        return;
    }

    for (auto const &it : g_arp)
    {
        cout << setw(25) << it.first
             << " / "
             << it.second << "\n";
    }
}

// transport protocol stats
void show_tr_proto(void)
{
    show_sub_header("Transport layer protocols");

    if (g_tr_proto.size() == 0)
    {
        cout << "(None found.)\n";
        return;
    }

    for (auto const &it : g_tr_proto)
    {
        const u_int8_t  x = it.first;
        const int       n = it.second;
        const u_int32_t s = sum_values(g_tr_proto);
        const double    p = double(n) * 100 / s;

        string type;

        if (x == IPPROTO_TCP)
        {
            type = "TCP";
        }
        else if (x == IPPROTO_UDP)
        {
            type = "UDP";
        }
        else if (x == IPPROTO_ICMP)
        {
            type = "ICMP";
        }
        else
        {
            stringstream ss;
            ss.setf(ios::hex, ios::basefield);
            ss.setf(ios::showbase);
            ss << hex << int(x);
            type = ss.str();
        }

        cout << setw(25) << setfill(' ') << type
             << setw(5) << n
             << setw(10) << setprecision(5) << p << " %\n";
    }
}

// This is where we call the all-important PCAP_LOOP()!  All bow
// before the mighty PCAP_LOOP()!
void run_pcap_loop(const char *infile)
{
    char errors[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(infile, errors);

    if (!handle)
    {
        cerr << "error opening " << infile
             << " [reason:" << errors << "]\n";
        exit(1);
    }

    int rc = pcap_datalink(handle);

    // LINKTYPE_ETHERNET == 1 == DLT_EN10MB
    if (rc != DLT_EN10MB)
    {
        cerr << "not an ethernet capture; we don't care";
        exit(1);
    }

    u_char user;

    if (pcap_check_header(infile) == false)
    {
        cerr << "input file appears to be corrput.\n";
        return;
    }

    rc = pcap_loop(handle, 0, pcap_callback, &user);

    switch (rc)
    {
    case 0:
        verbose("done reading: end of file (rc=%d)", rc);
        break;
    case -1:
        cerr << "done reading: error in file (rc=" << rc <<")\n";
        break;
    case -2:
        cerr << "done reading: pcap_breakloop (rc=" << rc << ")\n";
        break;
    default:
        cerr << "done reading: unknown reason (rc=" << rc << ")\n";
        break;
    }

    pcap_close(handle);
}

// display results once run_pcap_loop() has run its course.
void show_stats(void)
{
    show_summary();

    show_header("link layer");

    show_percentage("Souce ethernet addresses", g_eth_srcs);
    show_percentage("Destination ethernet addresses", g_eth_dsts);

    show_header("network layer");
    show_ip_proto_stats();
    show_percentage("Source IP addresses", g_ip_srcs);
    show_percentage("Destination IP addresses", g_ip_dsts);
    show_percentage("TTLs", g_ip_ttls);
    show_arp_parties();

    show_header("Transport layer");
    show_tr_proto();

    show_header("Transport layer: TCP");
    show_percentage("TCP source ports", g_tcp_src_ports);
    show_percentage("TCP destination ports", g_tcp_dst_ports);
    show_percentage("TCP flags", g_tcp_flags);
    show_percentage("TCP options", g_tcp_options, true);

    show_header("Transport layer: UDP");
    show_percentage("UDP source ports", g_udp_src_ports);
    show_percentage("UDP destination ports", g_udp_dst_ports);

    show_header("Transport layer: ICMP");
    show_percentage("ICMP sources", g_icmp_srcs);
    show_percentage("ICMP destinations", g_icmp_dsts);
    show_percentage("ICMP types", g_icmp_types);
    show_percentage("ICMP codes", g_icmp_codes);
    show_percentage("ICMP responses", g_icmp_responses);
}

void show_usage(const char *prog)
{
    cout << "\n Will read pcap files for food!\n"
         << "----------------------------------------------\n"
         << "Usage: " << prog << " [options] [capture file]\n"
         << "Options are:\n"
         << "\t -h \t Print this message and exit.\n"
         << "\t -v \t Run verbosely"
         << "\n\n";

    cout << "briefcap.exe looks at a pcap-format capture file \n"
         << "(usually created by wireshark, tshark, tcpdump etc)\n"
         << "and marvels at its contents, usually by printing out\n"
         << "a summary of the said contents.\n\n"
         << "briefcap.exe is interested only in ethernet, IPv4, TCP,\n"
         << "UDP and ICMP. Everything else is summarily rejected.\n"
         << "Sometimes a look of scorn is given.\n\n";
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        cerr << "usage: " << argv [0] << " <pcapfile>\n";
        exit(1);
    }

    int c;

    while ((c = getopt(argc, argv, "vh")) != -1)
    {
        switch (c)
        {
        case 'v':
            g_verbose_flag = 1;
            break;
        case 'h':
            show_usage(argv[0]);
            exit(1);
        default:
            abort();
        }
    }

    const char *infile = argv[optind];

    run_pcap_loop(infile);
    show_stats();

    return 0;
}
