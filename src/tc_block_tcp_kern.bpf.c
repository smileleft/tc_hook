#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h> // For struct tcphdr and TCP_FLAG_SYN
#include <bpf/bpf_helpers.h> // For BPF helper functions
#include <bpf/bpf_endian.h>    // For bpf_htons, bpf_ntohs
#include <linux/in.h>          // For IPPROTO_TCP definition
#include <linux/pkt_cls.h>

#define BLOCK_TCP_PORT 80 // Block TCP traffic to port 80 (HTTP)

char _license[] SEC("license") = "GPL"; // Required license declaration

// TC ingress hook
//SEC("tc") // Section name for TC programs
__attribute__((section("classifier"), used))
int tc_block_prog(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Start of Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        // Malformed packet or insufficient data, pass
        return TC_ACT_OK;
    }

    // Check if it's an IPv4 packet
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        // Not IPv4, pass
        return TC_ACT_OK;
    }

    // Start of IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)ip + sizeof(*ip) > data_end) {
        // Malformed IP header or insufficient data, pass
        return TC_ACT_OK;
    }

    if ((void *)ip + (ip->ihl * 4) > data_end) {
    	return TC_ACT_OK;
    }

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP) {
        // Not TCP, pass
        return TC_ACT_OK;
    }


    return TC_ACT_SHOT;
}
