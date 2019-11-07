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

/*
* prints raw packet
*/
void print_raw_packet(const unsigned char* pkt_data, long caplen) {
	printf(MYLINE);
	printf("RAW PACKET:\n\n");

	for (int i = 0; i < caplen; i++) {
		printf("%02x ", pkt_data[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n\n");
}


void print_ether_header(const unsigned char* pkt_data) {
	struct ether_header *myheader = (struct ether_header *)pkt_data;
	unsigned short et = ntohs(myheader->ether_type);
	// ====
	printf("ETHERNET HEADER\n\nDest MAC: ");

	for (int i = 0; i < 5; i++) {
		printf("%02x:", myheader->ether_dhost.ether_addr_octet[i]);
	}
	printf("%02x\n", myheader->ether_dhost.ether_addr_octet[5]);

	// =====
	printf("Sour MAC: ");

	for (int i = 0; i < 5; i++) {
		printf("%02x:", myheader->ether_shost.ether_addr_octet[i]);
	}
	printf("%02x\n", myheader->ether_shost.ether_addr_octet[5]);

	// =====

	printf("Protocol type: ");
	if (et != 0x0800) {
		printf("Ethernet type isn't correct: %u\n\n", et);
		return;
	}
	else {
		printf("IP\n\n");
	}
}

int print_ip_header(const unsigned char* pkt_data) {
	struct ip_hdr *myheader = (struct ip_hdr *)pkt_data;
	printf("IP HEADER\n\n");

	// ip ver
	printf("IP ver: %d\n", myheader->ip_version);
	printf("IP header length: %d\n", myheader->ip_header_len * 4);
	printf("TOS: %d\n", myheader->ip_tos);
	printf("Total length: %d\n", ntohs(myheader->ip_total_length) + 14);
	printf("Identification: %u\n", ntohs(myheader->ip_id));
	printf("Flags: \n");
	if (myheader->ip_dont_fragment) {
		printf("- don't fragment\n");
	}
	if (myheader->ip_more_fragment) {
		printf("- more fragments\n");
	}
	printf("Fragment offset: %u\n", myheader->ip_frag_offset1);
	printf("TTL: %d\n", myheader->ip_ttl);
	if (myheader->ip_protocol == 0x06)
	{
		printf("Protocol : TCP\n");
	}
	printf("Header checksum: %d\n", ntohs(myheader->ip_checksum));
	char scraddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(myheader->ip_srcaddr), scraddr, INET_ADDRSTRLEN);
	char dstaddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(myheader->ip_destaddr), dstaddr, INET_ADDRSTRLEN);
	printf("Source IP: %s\n", scraddr);
	printf("Destination IP: %s\n\n", dstaddr);

	// return offset for the next block
	return myheader->ip_header_len * 4;
}

int print_tcp_header(const unsigned char* pkt_data) {
	struct tcp_hdr* myheader = (struct tcp_hdr*)pkt_data;
	printf("TCP HEADER\n\n");
	printf("Source port number: %d\n", ntohs(myheader->source_port));
	printf("Destination port number: %d\n", ntohs(myheader->dest_port));
	printf("Sequence number: %d\n", ntohl(myheader->sequence));
	printf("Acknowledgement number: %d\n", ntohl(myheader->acknowledge));
	printf("Flags:\n");
	if (ntohs(myheader->cwr))
	{
		printf("- CWR\n");
	}
	if (ntohs(myheader->ecn))
	{
		printf("- ENC\n");
	}
	if (ntohs(myheader->urg))
	{
		printf("- URG\n");
	}
	if (ntohs(myheader->ack))
	{
		printf("- ACK\n");
	}
	if (ntohs(myheader->psh))
	{
		printf("- PUSH\n");
	}
	if (ntohs(myheader->rst))
	{
		printf("- RST\n");
	}
	if (ntohs(myheader->syn))
	{
		printf("- SYN\n");
	}
	if (ntohs(myheader->fin))
	{
		printf("- FIN\n");
	}
	printf("Window size: %d\n", ntohs(myheader->window));
	printf("TCP checksum: %d\n", ntohs(myheader->checksum));
	printf("Urgent pointer: %d\n\n", ntohs(myheader->urgent_pointer));
	// return offset
	return myheader->data_offset * 4;
}

void print_data(const unsigned char* pkt_data) {
	printf("DATA\n\n");
	printf("%s\n", pkt_data);
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

	char a[22] = "host learn.inha.ac.kr";

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
	struct pcap_pkthdr* header;
	const unsigned char* pkt_data;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {// 1 if success
		if (res == 0) continue; // 0 if time-out
		print_raw_packet(pkt_data, header->caplen);
		print_ether_header(pkt_data);
		pkt_data += 14;
		offset =  print_ip_header(pkt_data);
		pkt_data += offset;
		offset = print_tcp_header(pkt_data);
		pkt_data += offset;
		print_data(pkt_data);
	}
	
	struct timeval this_ts = header->ts; // timestamp of this packet
	double pkt_time = this_ts.tv_sec + this_ts.tv_usec / 1.0e6; // time value of this packet

	char timestr[256];
	printf(timestr, "%d.%06d", (int)this_ts.tv_sec, (int)this_ts.tv_usec);  // disply sec and usec
	printf("sec and usec:%s\n", timestr);
	printf("packet timestamp:%f\n", pkt_time); // display timestamp


	return 0;
}
