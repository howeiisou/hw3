#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

char matches[1024][128];
int matches_len = 0;
int matches_cnt[1024] = {0};
int print = 0;
char type[8] = "ALL";

int pkt_cnt = 0;
int pkt_size = 0;
int p_pkt = 0;

#define MAC_ADDRSTRLEN 18

static void pcap_callback2(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

int find_match(char tmp[])
{
	int i;
	for (i = 0; i < matches_len; i++)
	{
		if (strcmp(matches[i], tmp) == 0)
		{
			return i;
		}
	}
	return i;
}

char *mac_ntoa(u_char *d)
{
	static char str[MAC_ADDRSTRLEN] = {0};

	snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
	return str;
}

int main(int argc, const char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = NULL;
	int c = 0;

	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-p") == 0)
			print = 1;
		if (strcmp(argv[i], "-type") == 0)
		{
			strcpy(type, argv[i + 1]);
		}
		if (strcmp(argv[i], "-count") == 0)
			p_pkt = 1;
		if (strcmp(argv[i], "-c") == 0)
		{
			c = atoi(argv[i + 1]);
		}
	}

	if (argc > 2 && strcmp("-r", argv[1]) == 0)
	{
		pcap_t *handle = NULL;

		handle = pcap_open_offline(argv[2], errbuf);
		if (!handle)
		{
			fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
			exit(1);
		} //end if

		//start capture pcap_dispatch()
		pcap_loop(handle, c, pcap_callback2, NULL);

		//free
		pcap_close(handle);
	}
	else
	{
		if (!c)
			c = 10;
		device = pcap_lookupdev(errbuf);
		if (!device)
		{
			fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
			exit(1);
		} //end if

		printf("Sniffing: %s\n", device);

		pcap_t *handle = NULL;
		//open interface
		handle = pcap_open_live(device, 65535, 1, 1, errbuf);
		if (!handle)
		{
			fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
			exit(1);
		} //end if

		//start capture pcap_loop()
		if (0 > pcap_loop(handle, c, pcap_callback2, NULL))
		{
			fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
		} //end if
	}

	for (int i = 0; i < matches_len; i++)
	{
		printf("%s : %d times\n", matches[i], matches_cnt[i]);
	}

	if (p_pkt)
	{
		printf("\ntotal packet : %d\n", pkt_cnt);
		printf("total packet size : %d\n", pkt_size);
	}

	return 0;
} //end main

static void pcap_callback2(u_char *arg, const struct pcap_pkthdr *header, const u_char *content)
{
	static int d = 0;
	struct ether_header *ethernet = (struct ether_header *)content;

	printf("No. %3d\n", ++d);
	pkt_cnt++;
	pkt_size += header->len;
	//format timestamp
	struct tm *ltime;
	char timestr[30];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", ltime);

	//print header
	printf("Time:\t%s.%.6d\n", timestr, (int)header->ts.tv_usec);
	printf("Length: %d bytes\n", header->len);
	printf("Capture length: %d bytes\n", header->caplen);

	char ether_smac[MAC_ADDRSTRLEN] = {'\0'};
	char ether_dmac[MAC_ADDRSTRLEN] = {'\0'};

	strncpy(ether_smac, mac_ntoa(ethernet->ether_shost), 17);
	strncpy(ether_dmac, mac_ntoa(ethernet->ether_dhost), 17);

	// printf("Source mac address :\t\t%17s\nDestination mac address :\t%17s\n", ether_smac, ether_dmac);
	printf("+-------------------------+-------------------------+-------------------------+\n");
	printf("| Destination MAC Address:                                   %17s|\n", ether_dmac);
	printf("+-------------------------+-------------------------+-------------------------+\n");
	printf("| Source MAC Address:                                        %17s|\n", ether_smac);
	printf("+-------------------------+-------------------------+-------------------------+\n");
	switch (ntohs(ethernet->ether_type))
	{
	case ETHERTYPE_ARP:
		if (strcmp(type, "ALL"))
		{
			printf("ether_type :\tARP\n\n");
		}
		break;

	case ETHERTYPE_REVARP:
		if (strcmp(type, "ALL"))
		{
			printf("ether_type :\tRARP\n\n");
		}
		break;

	case ETHERTYPE_IPV6:
		if (strcmp(type, "ALL"))
		{
			printf("ether_type :\tIPv6\n\n");
		}
		break;

	case ETHERTYPE_IP:
	{
		if (strcmp(type, "ALL") == 0 || strcmp(type, "TCP") == 0 || strcmp(type, "UDP") == 0)
		{
			printf("ether_type :\tIPv4\n");
			struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
			char tmp[128], src[64];
			int cnt;
			memset(tmp, '\0', sizeof(tmp));
			strcpy(src, inet_ntoa(ip->ip_src));
			sprintf(tmp, "%s -> %s", src, inet_ntoa(ip->ip_dst));
			printf("%s\n", tmp);
			if ((cnt = find_match(tmp)) != matches_len)
			{
				matches_cnt[cnt]++;
			}
			else
			{
				matches_len++;
				strcpy(matches[cnt], tmp);
				matches_cnt[cnt]++;
			}
			switch (ip->ip_p)
			{
			case IPPROTO_UDP:
			{
				if (strcmp(type, "UDP") == 0 || strcmp(type, "ALL") == 0)
				{
					struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
					u_int16_t len = ntohs(udp->uh_ulen);
					u_int16_t checksum = ntohs(udp->uh_sum);

					printf("protocol :\tUDP\n");
					// printf("%s\t%d -> %d\n\n", tmp, ntohs(udp->uh_sport), ntohs(udp->uh_dport));
					printf("+-------------------------+-------------------------+\n");
					printf("| Source Port:       %5u| Destination Port:  %5u|\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
					printf("+-------------------------+-------------------------+\n");
					printf("| Length:            %5u| Checksum:          %5u|\n", len, checksum);
					printf("+-------------------------+-------------------------+\n\n");
					break;
				}
			}
			case IPPROTO_TCP:
			{
				if (strcmp(type, "TCP") == 0 || strcmp(type, "ALL") == 0)
				{
					struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
					u_int8_t header_len = tcp->th_off << 2;
					u_int8_t flags = tcp->th_flags;
					u_int16_t window = ntohs(tcp->th_win);
					u_int16_t checksum = ntohs(tcp->th_sum);
					u_int16_t urgent = ntohs(tcp->th_urp);

					printf("protocol :\tTCP\n");
					printf("+-------------------------+------------------------+\n");
					printf("| Source Port:       %5u| Destination Port:  %5u|\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
					printf("+-------------------------+-------------------------+\n");
					printf("| Checksum:          %5u                          |\n", checksum);
					printf("+---------------------------------------------------+\n\n");
					break;
				}
			}
			case IPPROTO_ICMP:
				if (strcmp(type, "ALL") == 0)
				{
					printf("protocol :\tICMP\n\n");
				}
				break;
			default:
				if (strcmp(type, "ALL") == 0)
				{
					printf("protocol :\t%d\n\n", ip->ip_p);
				}
				break;
			}
			break;
		}
	}

	default:
		printf("ether_type : %#06x\n", ethernet->ether_type);
		break;
	}

	if (print)
	{
		//print packet in hex dump
		for (int i = 0; i < header->caplen; i++)
		{
			printf("%02x ", content[i]);
		} //end for
		printf("\n\n");
	}
} //end pcap_callback2