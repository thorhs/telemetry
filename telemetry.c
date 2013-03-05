#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pcre.h>
#include <time.h>
#include <pthread.h>
#include "btree.h"
#include "btreep.h"

#define BUFFSIZE 2048
#define LISTEN_PORT 12345

#define min(a, b) ((a<b) ? a : b )	
#define max(a, b) ((a>b) ? a : b )	

static pcre *re;
static pcre_extra *sd;

void Die(char *msg) {
	perror(msg);
	exit(1);
}

struct telemetry_id {
	char what[16];
	char env[6];
	char host[10];
	char process[32];
	char datapoint[64];
};

struct telemetry {
	struct telemetry_id id;
	unsigned long int count;
	unsigned long int sum;
	unsigned long int max;
	unsigned long int min;
};

int compare_telemetry(const void *a, const void *b) {
	return(memcmp(a, b, sizeof(struct telemetry_id)));
}

int parse_string(BTREE tree, char *msg) {
	struct telemetry tel;
	struct telemetry *tel_p = NULL;
	char data[10];

	int rc;
	int ovector[30];

	memset(&tel, 0, sizeof(tel));
	memset(data, 0, sizeof(data));

	rc = pcre_exec(
		re,
		sd,
		msg,
		strlen(msg),
		0,
		0,
		ovector,
		30);

	if( rc == -1 )
		return 1;
	if( rc < 0 ) {
		fprintf(stderr, "String '%s' did not match pattern or error: %d\n", msg, rc);
		return 1;
	}

	strncpy(tel.id.what,      msg+ovector[2],  min(sizeof(tel.id.what)-1,      ovector[3]   - ovector[2]));
	strncpy(tel.id.env,       msg+ovector[4],  min(sizeof(tel.id.env)-1,       ovector[5]   - ovector[4]));
	strncpy(tel.id.host,      msg+ovector[6],  min(sizeof(tel.id.host)-1,      ovector[7]   - ovector[6]));
	strncpy(tel.id.process,   msg+ovector[8],  min(sizeof(tel.id.process)-1,   ovector[9]   - ovector[8]));
	strncpy(tel.id.datapoint, msg+ovector[10], min(sizeof(tel.id.datapoint)-1, ovector[11]  - ovector[10]));
	strncpy(       data,      msg+ovector[12], min(sizeof(       data)-1,      ovector[13]  - ovector[12]));

	tel.count = 1;
	tel.sum = tel.max = tel.min = (int)(atof(data)*1000);

	if(btree_Search(tree, &tel.id, (void **)&tel_p)) {
		btree_Insert(tree, &tel);
	} else {
		tel_p->count = tel_p->count+1;
		tel_p->sum   = tel_p->sum  +tel.sum;
		tel_p->max   = max(tel_p->max, tel.max);
		tel_p->min   = min(tel_p->min, tel.min);
	}

	return 0;
}

void tel_print_tree(BTREE tree, btnode node, time_t report_time)
{
	struct telemetry *tel;
	if(node == NULL) return;

	tel = (struct telemetry*)data(tree, node);

	/*fprintf(stderr, "%-*s%-*s%-*s%-*s%-*s: count:%lu sum:%lu max:%lu min:%lu\n",*/
	fprintf(stderr, "%s.%s.%s.%s.%s.%s %lu %lu", tel->id.what, tel->id.env, tel->id.process, tel->id.datapoint, tel->id.host, "count", tel->count, report_time);
	fprintf(stderr, "%s.%s.%s.%s.%s.%s %lu %lu", tel->id.what, tel->id.env, tel->id.process, tel->id.datapoint, tel->id.host, "sum"  , tel->sum, report_time);
	fprintf(stderr, "%s.%s.%s.%s.%s.%s %lu %lu", tel->id.what, tel->id.env, tel->id.process, tel->id.datapoint, tel->id.host, "min"  , tel->min, report_time);
	fprintf(stderr, "%s.%s.%s.%s.%s.%s %lu %lu", tel->id.what, tel->id.env, tel->id.process, tel->id.datapoint, tel->id.host, "max"  , tel->max, report_time);

  if (node) {
    tel_print_tree(tree, left(node), report_time);
    tel_print_tree(tree, right(node), report_time);
  }
}

time_t interval=10;
BTREE tree = NULL;

void *summarize_thread(void *thread_data) {
	time_t last_run=time(NULL);
	time_t now=0;
	time_t sleep_time=0;
	BTREE oldtree;
	BTREE newtree;

	while(1) {
		now=time(NULL);
		sleep_time = last_run + interval - now;
		sleep(sleep_time);
		last_run=time(NULL);

		newtree = btree_Create(sizeof(struct telemetry), compare_telemetry);
		oldtree = tree;
		tree = newtree;

		tel_print_tree(oldtree, oldtree->root, last_run);

		btree_Destroy(oldtree);
		fprintf(stderr, "+");
		exit(0);
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	int sock = 0;
	unsigned int srvaddr_len = 0;
	unsigned int clntaddr_len = 0;
	ssize_t received = 0;
	struct sockaddr_in6 srvaddr;
	struct sockaddr_in6 clntaddr;
	char recv_buffer[BUFFSIZE];

	const char *error;
	int erroroffset;

	unsigned long recv_count=0;

	pthread_t timer_thread;

	tree = btree_Create(sizeof(struct telemetry), compare_telemetry);

	re = pcre_compile(
	      /*K0:CERT:emghlc269:BookingStorageQueueReader:Retrieve and parse for [AUOLXZ].[2013-03-01 13:55:00] was 0.056 secs*/
		"^([[:alnum:]]+):([[:alnum:]]+):([[:alnum:]]+):([[:alnum:]]+): *(.*) for.* was ([0-9.]+).*", /* was ([0-9.]?) secs.*$",*/
		0,
		&error,
		&erroroffset,
		NULL);

	if ( re == NULL ) {
		fprintf(stderr, "PCRE compilation failed at offset %d: %s\n", erroroffset, error);
	}

	sd = pcre_study(
		re,
		PCRE_STUDY_JIT_COMPILE,
		&error);

	if ( sd == NULL ) {
		fprintf(stderr, "PCRE study failed: %s\n", error);
	}

	if((sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		Die("Unable to open socket");

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin6_family = AF_INET6;
	srvaddr.sin6_addr = in6addr_any;
	srvaddr.sin6_port = htons(LISTEN_PORT);

	srvaddr_len = sizeof(srvaddr);
	if(bind(sock, (struct sockaddr *) &srvaddr, srvaddr_len) < 0) 
		Die("Unable to bind server socket");

	pthread_create(&timer_thread, NULL, summarize_thread, NULL);

	while (1) {
		recv_count = recv_count + 1;
		clntaddr_len = sizeof(clntaddr);

		memset(recv_buffer, 0, sizeof(recv_buffer));
		if((received = recvfrom(sock, recv_buffer, BUFFSIZE, 0,
					(struct sockaddr *) &clntaddr,
					&clntaddr_len)) < 0)
			Die("Failed to receive message");

		parse_string(tree, recv_buffer);
		fprintf(stderr, ".");
	}

	return 0;
}
