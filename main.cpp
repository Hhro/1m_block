#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <iostream>
#include <unordered_set>
#include <sstream>
#include <fstream>

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}

#define METHOD_CNT 6

std::unordered_set<std::string> blocked_host;

void process_host_file(char *host_file){
	std::ifstream infile(host_file);
	std::string line;
	std::string host;

	while(std::getline(infile, line)){
		std::istringstream iss(line);
		host = line.substr(line.find(",")+1);
		blocked_host.insert(host);
	}
}

const char *http_methods[METHOD_CNT] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
;
int methods_len[METHOD_CNT] = {3, 4, 4, 3, 6, 7};

void usage()
{
	puts("./1m_block <block_host_file>");
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			  struct nfq_data *nfa, void *block_host)
{
	struct nfqnl_msg_packet_hdr *ph;
	struct pkt_buff *pkt;
	struct iphdr *ip;
	struct tcphdr *tcp;
	int id = 0;
	int payload_len;
	int tcp_payload_len;
	std::string host;
	uint8_t *payload;
	uint8_t *tcp_payload;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
	{
		id = ntohl(ph->packet_id);
	}

	payload_len = nfq_get_payload(nfa, &payload);
	pkt = pktb_alloc(AF_INET, payload, payload_len, 0);
	ip = nfq_ip_get_hdr(pkt);
	nfq_ip_set_transport_header(pkt, ip);
	tcp = nfq_tcp_get_hdr(pkt);

	if (tcp){
		tcp_payload_len = nfq_tcp_get_payload_len(tcp, pkt) - tcp->doff * 4;
		if (tcp_payload_len > 0){
			tcp_payload = (uint8_t *)nfq_tcp_get_payload(tcp, pkt);

			for (int i = 0; i < METHOD_CNT; i++){
				if (!memcmp(tcp_payload, http_methods[i], methods_len[i])){
					host = std::string(reinterpret_cast<char*>(tcp_payload));
					if (host.find("Host: ") != std::string::npos){
						host = host.substr(host.find("Host: ")+6);
						if(blocked_host.find(host) != blocked_host.end()){
							std::cout << "Blocked host " <<  host;
							pktb_free(pkt);
							return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
						}
					}
				}
			}
		}
	}

	pktb_free(pkt);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[4096] __attribute__((aligned));
	char *block_host;
	int fd;
	int rv;

	if (argc != 2)
	{
		usage();
		return -1;
	}

	process_host_file(argv[1]);

	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	qh = nfq_create_queue(h, 0, &cb, block_host);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		exit(1);
	}

	fd = nfq_fd(h);
	puts("HELLO");

	while (1)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS)
		{
			continue;
		}
		break;
	}

	nfq_destroy_queue(qh);
	nfq_close(h);
}