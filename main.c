#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHERTYPE_IP 0x0800

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    printf("\n*** Packet Captured (Length: %d bytes) ***\n", pkthdr->len);

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        
        struct in_addr src_ip, dest_ip;
        src_ip.s_addr = ip_header->saddr;
        dest_ip.s_addr = ip_header->daddr;

        printf("Source IP: %s\n", inet_ntoa(src_ip));
        printf("Destination IP: %s\n", inet_ntoa(dest_ip));

        switch (ip_header->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4));
                printf("Protocol: TCP\n");
                printf("Source Port: %d\n", ntohs(tcp_header->source));
                printf("Destination Port: %d\n", ntohs(tcp_header->dest));
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4));
                printf("Protocol: UDP\n");
                printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
                printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
                break;
            }
            default:
                printf("Protocol: Other (Protocol Number: %d)\n", ip_header->protocol);
                break;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevs, *dev;
    
    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    dev = alldevs;  // Selecting the first available device
    if (!dev) {
        printf("No devices found.\n");
        return 1;
    }

    printf("Using device: %s\n", dev->name);

    // Open the device for packet capture
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        printf("Could not open device %s: %s\n", dev->name, errbuf);
        return 1;
    }

    // Capture packets
    pcap_loop(handle, 10, packet_handler, NULL);

    // Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 0;
}
