#include <pcap.h>
#include <strings.h>
#include <cstdio>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct EthernetHeader{
    uint8_t dst[6]; //8bit * 6 (6byte)
    uint8_t src[6]; //8bit * 6 (6byte)
    uint16_t type; //16bit (2byte)
};

struct IpHeader{
    uint8_t vhl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t cksum;
    uint8_t sip[4];
    uint8_t dip[4];
};

struct TcpHeader{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flag; // hlen(4), reservbit(6), urg(1), ack(1), psh(1), rst(1), syn(1), fin(1)
    uint16_t win_size;
    uint16_t cksum;
    uint16_t urpoint;
    uint8_t data[32];
};

void pcap_mac(uint8_t* mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void pcap_ip(uint8_t* ip){
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}
void pcap_data(uint8_t* data){
    printf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]);
}
    void usage() {
        printf("syntax: pcap_test <interface>\n");
        printf("sample: pcap_test wlan0\n");}

    int main(int argc, char* argv[]) {
      if (argc != 2) {
        usage();
        return -1;
      }
      //uint8_t ippacket_len = 0;
      //uint8_t total_header = 0;
      //uint8_t tcppacket_len = 0;
      uint8_t total_len = 0;

      int *packet;
      char* dev = argv[1];
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
      }

      while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthernetHeader *eth = (EthernetHeader*) packet;
        IpHeader *ip = (IpHeader*) (packet + 14);
        TcpHeader *tcp = (TcpHeader*) (packet + 34);
        if(ntohs(eth->type) == 0x0800){
            if(ip->protocol == 6){
                    printf("Dmac : ");
                    pcap_mac(eth->dst);
                    printf("Smac : ");
                    pcap_mac(eth->src);
                    printf("S-ip : ");
                    pcap_ip(ip->sip);
                    printf("D-ip : ");
                    pcap_ip(ip->dip);
                    printf("S-port : %d\n", ntohs(tcp->sport));
                    printf("D-port : %d\n", ntohs(tcp->dport));
                    //ippacket_len = ((ip->vhl)&0xf) * 4 ;//& 0xf >>4 20
                    //tcppacket_len = (ntohs(tcp->flag)>>12) * 4;//20
                    //total_header = 14 + ippacket_len + tcppacket_len;
                    printf("Data : ");
                    total_len = ntohs(ip->total_len) + 14;
                    pcap_data(&total_len);
                    printf("%u bytes captured\n", header->caplen);
                    printf("\n");
                }
            else{printf("No IP Packet...\n");
                printf("\n");
                }
            }
        else {
           printf("No TCP Packet...\n");
            printf("\n");}
      }
          pcap_close(handle);
          return 0;
}
