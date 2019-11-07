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

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

// 
unsigned short in_checksum(unsigned short* ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)& oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (SHORT)~sum;  // use “short” in MacOS

	return(answer);
}

// build packet
unsigned char* build_packet(const unsigned char* pkt_data, int caplen) {
	// my headers
	struct ether_header* myeh;
	struct ip_hdr* myih;
	struct tcp_hdr* myth;

	unsigned char packet[65535];    // max packet size is 65535
	for (unsigned int i = 0; i < caplen; i++) {
		packet[i] = pkt_data[i];
	}

	// build ethernet header
	myeh = (struct ether_header*)packet;

	// build ip header
	myih = (struct ip_hdr*)(packet + 14);
	myih->ip_checksum = 0;
	myih->ip_checksum = in_checksum((unsigned short*)myih, 20);

	myth = (struct tcp_hdr*)packet + 14 + 20;
	myth->checksum = 0;
	size_t tcp_header_len = myth->data_offset * 4;

	struct pseudo_header psh;
	psh.source_address = myih->ip_srcaddr;
	psh.dest_address = myih->ip_destaddr;
	psh.placeholder = 0;  // reserved
	psh.protocol = 6;  // protocol number for tcp
	psh.tcp_length = htons(tcp_header_len); // store multi byte number in network byte order

	unsigned char* seudo = (unsigned char*)malloc(sizeof(struct pseudo_header) + tcp_header_len);
	memcpy(seudo, &psh, sizeof(struct pseudo_header));
	memcpy(seudo + sizeof(struct pseudo_header), myth, tcp_header_len);

	myth->checksum = in_checksum((unsigned short*)seudo, sizeof(struct pseudo_header) + tcp_header_len);

	printf("NEW RAW PACKET:\n\n");

	for (int i = 0; i < caplen; i++) {
		printf("%02x ", packet[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n\n");

	return packet;
}

bool captureSYN(const unsigned char* pkt_data, long caplen) {
	struct ether_header* myheader = (struct ether_header*)pkt_data;
	const unsigned char* data = pkt_data;
	pkt_data += 14;
	struct ip_hdr* ipheader = (struct ip_hdr*)pkt_data;
	pkt_data += ipheader->ip_header_len * 4;
	struct tcp_hdr* tcpheader = (struct tcp_hdr*)pkt_data;

	if ((ntohs(tcpheader->syn)) && !(ntohs(tcpheader->ack)))
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
				unsigned char* packet = build_packet(pkt_data, header->caplen);
				if (pcap_sendpacket(fp, packet, header->caplen) != 0) {
					printf("err in packet send:%s\n", pcap_geterr(fp));
				}
				else {
					printf("Packet sent\n");
				}
			}
			break;
		}
	}

	return 0;
}
