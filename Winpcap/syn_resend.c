#include <stdio.h>
#include "pcap.h"
#include <winsock2.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define MYLINE "===============================================\n"

struct ether_addr {
	unsigned char ether_addr_octet[6];
};

struct ether_header {
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;          // 0x0800 for IP
};

struct ip_hdr {
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
};

struct tcp_hdr {
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

bool captureSYN(const unsigned char* pkt_data, long caplen) {
	struct ether_header* myheader = (struct ether_header*)pkt_data;
	const unsigned char* data = pkt_data;
	pkt_data += 14;
	struct ip_hdr* ipheader = (struct ip_hdr*)pkt_data;
	pkt_data += ipheader->ip_header_len * 4;
	struct tcp_hdr* tcpheader = (struct tcp_hdr*)pkt_data;

	if (ntohs(tcpheader->syn))
	{
		printf(MYLINE);
		printf("SYN CAPTURED!\n\nRAW PACKET:\n\n");

		for (int i = 0; i < caplen; i++) {
			printf("%02x ", data[i]);
			if ((i + 1) % 16 == 0) printf("\n");
		}
		printf("\n\n");
		return true;
	}
	return false;
}

int main() {
	struct pcap_pkhdr {  // defined in pcap.h
		struct timeval ts; // time stamp
		bpf_u_int32 caplen; // length of portion present
		bpf_u_int32 len; // length of this packet
	};

	pcap_if_t* alldevs;
	pcap_t* adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}

	// print them
	pcap_if_t* d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	int inum;
	printf("enter the interface number: ");
	scanf_s("%d", &inum);
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the inum-th dev

	// open
	pcap_t* fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
	)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("pcap open successful\n");

	char a[35] = "host 165.246.38.151 and port 12194";

	struct bpf_program  fcode;
	if (pcap_compile(fp,  // pcap handle
		&fcode,  // compiled rule
		a,  // filter rule
		1,            // optimize
		NULL) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) < 0) {
		printf("pcap setfilter failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("filter setting successful\n");
	pcap_freealldevs(alldevs); // we don't need this anymore
	// capture. you have to implement print_raw_packet, print_ether_header, etc.

	int offset = 0;
	char des;
	struct pcap_pkthdr* header;
	const unsigned char* pkt_data;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {// 1 if success
		if (res == 0) continue; // 0 if time-out
		if (captureSYN(pkt_data, header->caplen)) {
			printf("To send packet press [y / n] : ");
			//getchar();
			scanf_s(" %c", &des, 1);
			if (des == 'y') {
				pcap_sendpacket(fp, pkt_data, header->caplen);
				printf("Packet sent\n");
			}
			break;
		}
	}

	return 0;
}
