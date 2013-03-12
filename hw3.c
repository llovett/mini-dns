#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "dns.h"
#include "linkedlist.h"

static int debug=0;

void usage() {
    printf("Usage: hw2 [-d] [-n nameserver] -i domain/ip_address\n\t-d: debug\n");
    exit(1);
}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) {
    memset(query,0,max_query);

    in_addr_t rev_addr=inet_addr(hostname);
    if(rev_addr!=INADDR_NONE) {
	static char reverse_name[255];
	sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
		(rev_addr&0xff000000)>>24,
		(rev_addr&0xff0000)>>16,
		(rev_addr&0xff00)>>8,
		(rev_addr&0xff));
	hostname=reverse_name;
    }

    // first part of the query is a fixed size header
    struct dns_hdr *hdr = (struct dns_hdr*)query;

    // generate a random 16-bit number for session
    uint16_t query_id = (uint16_t) (random() & 0xffff);
    hdr->id = htons(query_id);
    // set header flags to request recursive query
    hdr->flags = htons(0x0100);
    // 1 question, no answers or other records
    hdr->q_count=htons(1);

    // add the name
    int query_len = sizeof(struct dns_hdr);
    int name_len=to_dns_style(hostname,query+query_len);
    query_len += name_len;

    // now the query type: A or PTR.
    uint16_t *type = (uint16_t*)(query+query_len);
    if(rev_addr!=INADDR_NONE)
	*type = htons(12);
    else
	*type = htons(1);
    query_len+=2;

    // finally the class: INET
    uint16_t *class = (uint16_t*)(query+query_len);
    *class = htons(1);
    query_len += 2;

    return query_len;
}

char *resolve_address(char *hostname, linkedlist *nameservers) {
    // The hostname we'll be looking up in any recursive call
    char *newhostname = hostname;

    // Could we get ahold of the nameserver?
    int could_contact_ns = 0;

    // Stuff we'll use after getting ahold of a nameserver
    uint8_t answerbuf[1500];

    // Build a socket with a timeout
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
	perror("Creating socket failed: ");
	exit(1);
    }
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Loop to contact a nameserver
    while (!could_contact_ns) {
	// Try a nameserver
	in_addr_t nameserver_addr=inet_addr(nameservers->server_addr);

	// construct the query message
	uint8_t query[1500];
	int query_len=construct_query(query,1500,hostname);

	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	int send_count = sendto(sock, query, query_len, 0,
				(struct sockaddr*)&addr,sizeof(addr));
	if(send_count<0) {
	    perror("Send failed");
	    exit(1);
	}

	// Await the response
	int rec_count = recv(sock,answerbuf,1500,0);

	// Check for errors while receiving
	if ((rec_count < 1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
	    printf("Timed out while waiting for nameserver %s.\n", nameservers->server);
	    linkedlist *head = nameservers;
	    nameservers = nameservers->next;
	    free(head->server);
	    free(head);
	} else {
	    could_contact_ns = 1;
	}
    }

    // parse the response to get our answer
    struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
    uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);

    // now answer_ptr points at the first question.
    int question_count = ntohs(ans_hdr->q_count);
    int answer_count = ntohs(ans_hdr->a_count);
    int auth_count = ntohs(ans_hdr->auth_count);
    int other_count = ntohs(ans_hdr->other_count);

    // skip past all questions
    int q;
    for(q=0;q<question_count;q++) {
	char string_name[255];
	memset(string_name,0,255);
	int size=from_dns_style(answerbuf,answer_ptr,string_name);
	answer_ptr+=size;
	answer_ptr+=4; //2 for type, 2 for class
    }

    int a;
    int got_answer=0;

    // now answer_ptr points at the first answer. loop through
    // all answers in all sections
    linkedlist *new_nameservers = NULL;
    linkedlist *nn_head = NULL;
    for(a=0;a<answer_count+auth_count+other_count;a++) {
	// first the name this answer is referring to
	char string_name[255];
	int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
	answer_ptr += dnsnamelen;

	// then fixed part of the RR record
	struct dns_rr* rr = (struct dns_rr*)answer_ptr;
	answer_ptr+=sizeof(struct dns_rr);

	const uint8_t RECTYPE_A=1;
	const uint8_t RECTYPE_NS=2;
	const uint8_t RECTYPE_CNAME=5;
	const uint8_t RECTYPE_SOA=6;
	const uint8_t RECTYPE_PTR=12;
	const uint8_t RECTYPE_AAAA=28;

	if(htons(rr->type)==RECTYPE_A) {
	    char *ip_addr = inet_ntoa(*((struct in_addr *)answer_ptr));

	    printf("The name %s resolves to IP addr: %s\n",
		   string_name,
		   ip_addr);
	    got_answer=1;

	    // Are we done?
	    if ( !strcasecmp(string_name, hostname) ) {
		return ip_addr;
	    }

	    // Try to match some IPs up with symbolic hostnames for nameservers
	    linkedlist *node = nn_head;
	    while ( node ) {
		if ( !strcasecmp(string_name,node->server) ) {
		    node->server_addr = strdup(ip_addr);
		    break;
		}
		node = node->next;
	    }
	}
	// NS record
	else if(htons(rr->type)==RECTYPE_NS) {
	    char ns_string[255];
	    int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
	    if(debug)
		printf("The name %s can be resolved by NS: %s\n",
		       string_name, ns_string);
	    got_answer=1;
	    if ( NULL == new_nameservers ) {
		new_nameservers = list_new(ns_string);
		nn_head = new_nameservers;
	    } else {
		new_nameservers->next = list_new(ns_string);
		new_nameservers = new_nameservers->next;
	    }
	}
	// CNAME record
	else if(htons(rr->type)==RECTYPE_CNAME) {
	    char ns_string[255];
	    int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
	    if(debug)
		printf("The name %s is also known as %s.\n",
		       string_name, ns_string);
	    got_answer=1;

	    newhostname = ns_string;
	}
	// PTR record
	else if(htons(rr->type)==RECTYPE_PTR) {
	    char ns_string[255];
	    int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
	    printf("The host at %s is also known as %s.\n",
		   string_name, ns_string);
	    got_answer=1;
	}
	// SOA record
	else if(htons(rr->type)==RECTYPE_SOA) {
	    if(debug)
		printf("Ignoring SOA record\n");
	}
	// AAAA record
	else if(htons(rr->type)==RECTYPE_AAAA)  {
	    if(debug)
		printf("Ignoring IPv6 record\n");
	}
	else {
	    if(debug)
		printf("got unknown record type %hu\n",htons(rr->type));
	}

	answer_ptr+=htons(rr->datalen);
    }

    shutdown(sock,SHUT_RDWR);
    close(sock);

    new_nameservers = nn_head;
    if ( NULL != new_nameservers ) {
	linkedlist *node = nn_head;
	while ( node ) {
	    printf("nameserver: %s (ip: %s)\n", node->server, node->server_addr);
	    node = node->next;
	}

	return resolve_address(newhostname, new_nameservers);
    }
    // TODO:Free the nameservers linkedlist

    return NULL;
}

int main(int argc, char** argv)
{
    if(argc<2) usage();

    char *hostname=0;
    char *nameserver=0;

    char *optString = "-d-n:-i:";
    int opt = getopt( argc, argv, optString );

    while( opt != -1 ) {
	switch( opt ) {
	case 'd':
	    debug = 1;
	    break;
	case 'n':
	    nameserver = optarg;
	    break;
	case 'i':
	    hostname = optarg;
	    break;
	case '?':
	    usage();
	    exit(1);
	default:
	    usage();
	    exit(1);
	}
	opt = getopt( argc, argv, optString );
    }

    linkedlist *ns = (linkedlist *)malloc(sizeof(linkedlist));
    if (!nameserver) {
    	// Use root-servers.txt
    	FILE *servers_in = fopen("root-servers.txt","r");
    	if (!servers_in) {
    	    perror("fopen");
    	    exit(1);
    	}

    	char root_addr[256];
    	while ( EOF != fscanf(servers_in, "%s\n", &root_addr[0]) ) {
    	    ns->server_addr = strdup(&root_addr[0]);
    	}

    	fclose(servers_in);
    } else {
    	ns->server = strdup(nameserver);
    }

    if (!hostname) {
	usage();
	exit(1);
    }

    // Try to resolve the given servername or ip address
    char *result = resolve_address(hostname, ns);
    if ( result ) {
	printf("%s resolves to %s.\n", hostname, result);
    } else {
	printf("Could not resolve the name %s.\n", hostname);
    }
}
