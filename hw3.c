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

#define MAX_NAMESERVERS 100

typedef struct {
    char *server;
    char *server_addr;
} nameserver;

static int debug=0;
static nameserver *root_servers[MAX_NAMESERVERS];
static int num_root_servers;

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

char *resolve_address(char *hostname, nameserver **nameservers, int ns_count) {
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
    // TODO: change this to random index
    int chosen_server = 0;
    // The nameserver we'll be using to do the query
    nameserver *active_ns;
    while (!could_contact_ns) {
	// Try a nameserver
	active_ns = nameservers[chosen_server];
	in_addr_t nameserver_addr=inet_addr(active_ns->server_addr);

	// construct the query message
	uint8_t query[1500];
	int query_len=construct_query(query,1500,hostname);

	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	if (debug)
	    printf("How about nameserver %s?\n", active_ns->server_addr);

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
	    if (debug)
		printf("Timed out while waiting for nameserver %s.\n", active_ns->server_addr);

	    // TODO: try another random nameserver
	} else {
	    could_contact_ns = 1;
	}
    }

    if (debug) {
	printf("Resolving %s using server %s out of %d\n",
	       hostname, active_ns->server_addr, ns_count);
    }

    // parse the response to get our answer
    struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
    uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);

    // now answer_ptr points at the first question.
    int question_count = ntohs(ans_hdr->q_count);
    int answer_count = ntohs(ans_hdr->a_count);
    int auth_count = ntohs(ans_hdr->auth_count);
    int other_count = ntohs(ans_hdr->other_count);

    if (debug) {
	int resource_count = question_count + answer_count + auth_count + other_count;
	printf("%d questions, %d answers, %d authoritative records, and %d others = %d resource records total\n",
	       question_count, answer_count, auth_count, other_count, resource_count);
    }

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
    nameserver *new_nameservers[100];
    int ns_index = 0;
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

	    if (debug)
		printf("The name %s resolves to IP addr: %s\n",
		       string_name,
		       ip_addr);

	    got_answer=1;

	    // Are we done?
	    if ( !strcasecmp(string_name, newhostname) ) {
		return ip_addr;
	    }

	    // Try to match some IPs up with symbolic hostnames for nameservers
	    int i;
	    for ( i=0; i<ns_count; i++ ) {
		nameserver *new_ns = new_nameservers[i];
		if ( !strcasecmp(string_name,new_ns->server) ) {
		    new_ns->server_addr = strdup(ip_addr);
		    break;
		}
	    }
	}
	// NS record
	else if(htons(rr->type)==RECTYPE_NS) {
	    char ns_string[255];
	    int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
	    if(debug)
		printf("The name %s can be resolved by NS: %s\n",
		       string_name, ns_string);

	    // Keep maximum number of nameservers
	    if ( ns_index < MAX_NAMESERVERS ) {
		nameserver *new_ns = (nameserver*)malloc(sizeof(nameserver));
		new_ns->server = strdup(ns_string);
		new_nameservers[ns_index++] = new_ns;
	    }

	    got_answer=1;
	}
	// CNAME record
	else if(htons(rr->type)==RECTYPE_CNAME) {
	    char ns_string[255];
	    int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);

	    if(debug) {
		printf("The name %s is also known as %s.\n",
		       string_name, ns_string);
	    }

	    if ( !strcasecmp(string_name,hostname) ) {
		newhostname = strdup(ns_string);
	    }

	    got_answer=1;
	}
	// PTR record
	else if(htons(rr->type)==RECTYPE_PTR) {
	    char ns_string[255];
	    int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);

	    if (debug) {
		printf("The host at %s is also known as %s.\n",
		       string_name, ns_string);
	    }

	    got_answer=1;

	    return strdup(ns_string);
	}
	// SOA record
	else if(htons(rr->type)==RECTYPE_SOA) {
	    if(debug) {
		printf("Ignoring SOA record\n");
	    }
	}
	// AAAA record
	else if(htons(rr->type)==RECTYPE_AAAA)  {
	    if(debug) {
		printf("Ignoring IPv6 record\n");
	    }
	}
	else {
	    if(debug) {
		printf("got unknown record type %hu\n",htons(rr->type));
	    }
	}

	answer_ptr+=htons(rr->datalen);
    }

    shutdown(sock,SHUT_RDWR);
    close(sock);

    if ( ns_index > 0 ) {
	int i;
	for ( i=0; i<ns_index; i++ ) {
	    nameserver *ns = new_nameservers[i];
	    // Make sure we have the IP address of this nameserver
	    if ( !ns->server_addr ) {
		if (debug)
		    printf("Need to resolve IP address of nameserver %s\n", ns->server);
		ns->server_addr = resolve_address(ns->server, root_servers, num_root_servers);

		if ( !ns->server_addr && debug ) {
		    printf("Failed to retrieve IP address for %s.\n", ns->server);
		}
	    }
	}

	if (debug)
	    printf("now resolving the hostname %s...\n", newhostname);
	return resolve_address(newhostname, new_nameservers, ns_index);
    }
    // TODO:Free the nameservers array

    return NULL;
}

int main(int argc, char** argv)
{
    if(argc<2) usage();

    char *hostname=0;
    char *given_ns=0;

    char *optString = "-d-n:-i:";
    int opt = getopt( argc, argv, optString );

    while( opt != -1 ) {
	switch( opt ) {
	case 'd':
	    debug = 1;
	    break;
	case 'n':
	    given_ns = optarg;
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

    /* initialize root servers list */
    if (!given_ns) {
    	// Use root-servers.txt
	num_root_servers = 0;
    	FILE *servers_in = fopen("root-servers.txt","r");
    	if (!servers_in) {
    	    perror("fopen");
    	    exit(1);
    	}

    	char root_addr[256];
	for ( num_root_servers=0; num_root_servers<MAX_NAMESERVERS; num_root_servers++ ) {
	    if (EOF != fscanf(servers_in, "%s\n", &root_addr[0])) {
		nameserver *ns = (nameserver*)malloc(sizeof(nameserver));
		ns->server_addr = strdup(&root_addr[0]);
		root_servers[num_root_servers] = ns;
	    } else {
		fclose(servers_in);
		break;
	    }
	}

    } else {
	nameserver *ns = (nameserver*)malloc(sizeof(nameserver));
	ns->server_addr = strdup(given_ns);
	num_root_servers = 1;
    }

    if (!hostname) {
	usage();
	exit(1);
    }

    // Try to resolve the given servername or ip address
    char *result = resolve_address(hostname, root_servers, num_root_servers);
    if ( result ) {
	printf("%s resolves to %s\n", hostname, result);
    } else {
	printf("Could not resolve the name %s\n", hostname);
    }
}
