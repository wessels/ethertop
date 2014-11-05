#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <err.h>
#include <memory.h>
#include <pthread.h>
#include <curses.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
#include <net/route.h>


#include <pcap.h>

#define NCOUNTS 60
#define MAX_ESTAT 1024


/*
 * This is our data structure.  There shall be a simple hash table / linked list.
 * Since we never delete these, the only locking we need to worry about is
 * when rearranging the pointers in the main thread, or traversing the
 * list in a child thread.
 */

struct _estat {
	unsigned char addr[ETHER_ADDR_LEN];
	struct in_addr ipv4;
	char name[NI_MAXHOST];
	time_t name_lookup_time;
	unsigned int packets[NCOUNTS];
	unsigned int octets[NCOUNTS];
	struct _estat *next;
};

struct _estat *Stats_ll[256];
struct _estat *Stats_array[MAX_ESTAT];
unsigned int nstat = 0;
pthread_t threadDisplay;
pthread_t threadArpLookup;
pthread_t threadDnsLookup;
pthread_mutex_t mutex_S;
WINDOW *win = 0;
time_t last = 0;
char *arpdata = 0;
size_t arpsize = 0;

struct _estat *
lookup_ether(unsigned char addr[], int create)
{
	unsigned int bucket = addr[ETHER_ADDR_LEN-1];
	struct _estat *s;
	for (s = Stats_ll[bucket]; s; s = s->next) {
		if (0 == memcmp(s->addr, addr, ETHER_ADDR_LEN))
			return s;
	}
	if (!create)
		return 0;
	if (MAX_ESTAT == nstat)
		return 0;
	s = calloc(1, sizeof(*s));
	memcpy(s->addr, addr, ETHER_ADDR_LEN);
	pthread_mutex_lock(&mutex_S);
	s->next = Stats_ll[bucket];
	Stats_ll[bucket] = s;
	Stats_array[nstat] = s;
	nstat++;
	pthread_mutex_unlock(&mutex_S);
	return s;
}

void
account(unsigned char addr[], unsigned int len, time_t p)
{
	struct _estat *s = lookup_ether(addr, 1);
	s->packets[p]++;
	s->octets[p] += len;
}

void
clear_counts(time_t p)
{
	unsigned int i;
	for (i = 0; i < nstat; i++) {
		Stats_array[i]->packets[p] = 0;
		Stats_array[i]->octets[p] = 0;
	}
}

void
packet(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *pkt)
{
	struct ether_header *e = (struct ether_header *) pkt;
	unsigned int b = h->ts.tv_sec % NCOUNTS;
	if (h->ts.tv_sec > last)
		clear_counts((h->ts.tv_sec + 1) % NCOUNTS);
	account(e->ether_dhost, h->len, b);
	account(e->ether_shost, h->len, b);
	last = h->ts.tv_sec;
}

int
estat_sort(const void *A, const void *B)
{
	const struct _estat *a = *(struct _estat**)A;
	const struct _estat *b = *(struct _estat**)B;
	uint64_t va = 0;
	uint64_t vb = 0;
	unsigned int p;
	for (p = 0; p < NCOUNTS; p++) {
		va += a->packets[p];
		vb += b->packets[p];
	}
	if (va < vb)
		return 1;
	if (va > vb)
		return -1;
	if (a->addr[5] < b->addr[5])
		return 1;
	if (a->addr[5] > b->addr[5])
		return -1;
	return 0;
}


void
scan_arp()
{
	char *lim;
	char *next;
        struct rt_msghdr *rtm;
	struct sockaddr_dl *sdl;
	struct sockaddr_inarp *sin;
	struct _estat *s;
	lim = arpdata + arpsize;
	if (0 == arpdata)
		return;
	for (next = arpdata; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		sin = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)((char *)sin + SA_SIZE(sin));
		s = lookup_ether((unsigned char *) LLADDR(sdl), 0);
		if (!s)
			continue;
		memcpy(&s->ipv4, &sin->sin_addr, 4);
	}
}

char
graph1(unsigned int v)
{
	if (v > 512)
		return '#';
	if (v > 64)
		return 'O';
	if (v > 8)
		return 'o';
	if (v > 0)
		return '.';
	return ' ';
}

char
graph2(unsigned int v)
{
	if (v > 512)
		return '#';
	if (v > 64)
		return '~';
	if (v > 8)
		return '-';
	return '_';
}

double
avg_pps(struct _estat *s)
{
	unsigned int i;
	double val = 0.0;
	for (i = 0; i < NCOUNTS; i++)
		val += s->packets[i];
	return val / (NCOUNTS - 1);
}

double
avg_bps(struct _estat *s)
{
	unsigned int i;
	double val = 0.0;
	for (i = 0; i < NCOUNTS; i++)
		val += s->octets[i];
	return val / (NCOUNTS - 1);
}

void
display()
{
	unsigned int j = 2;
	unsigned int k;
	unsigned int i;
	int MX, MY;
	struct _estat *s;
	struct _estat **sortme = calloc(nstat+1, sizeof(*s));

	scan_arp();
	pthread_mutex_lock(&mutex_S);
	for (i = 0; i < nstat; i++)
		*(sortme+i) = Stats_array[i];
	pthread_mutex_unlock(&mutex_S);
	qsort(sortme, nstat, sizeof(*sortme), estat_sort);

	getmaxyx(win, MY, MX);
	MY--;
	for (k = 0; k < nstat; k++) {
		s = *(sortme+k);
		double pps = avg_pps(s);
		char abuf[20];
		if (0.0 == pps)
			continue;
		inet_ntop(AF_INET, &s->ipv4, abuf, sizeof(abuf));
		mvprintw(j, 0, "%02x:%02x:%02x:%02x:%02x:%02x  %15s  %30.30s",
			s->addr[0], s->addr[1], s->addr[2], s->addr[3], s->addr[4], s->addr[5],
			abuf, s->name);
		printw("  %6.1f  %6.1f", pps, 0.008 * avg_bps(s));
		move(j, 87);
		for (i = 0; i < NCOUNTS; i++) {
			unsigned int p = (i+last+1) % NCOUNTS;
			addch(graph1(s->packets[p]));
		}
		if (MY == ++j)
			break;
	}
	clrtobot();
	refresh();
	free(sortme);
}

void *
display_loop(void *unused)
{
	win = initscr();
	mvprintw(0, 0, "%17s  %15s  %30.30s  %6s  %6s", "Ether", "IPv4", "Name", "pps", "kb/s");
	for (;;) {
		display();
		sleep(1);
	}
	return 0;
}

void
fetch_arp()
{
	int mib[6];
	int st;

        mib[0] = CTL_NET;
        mib[1] = PF_ROUTE;
        mib[2] = 0;
        mib[3] = AF_INET;
        mib[4] = NET_RT_FLAGS;
        mib[5] = RTF_LLINFO;
        if (sysctl(mib, 6, NULL, &arpsize, NULL, 0) < 0) {
                perror("sysctl");
		return;
	}
        if (arpsize == 0)
                return;
	if (arpdata) {
		free(arpdata);
		arpdata = 0;
	}
        for (;;) {
                arpdata = reallocf(arpdata, arpsize);
                if (arpdata == NULL)
                        return;
                st = sysctl(mib, 6, arpdata, &arpsize, NULL, 0);
                if (st == 0 || errno != ENOMEM)
                        break;
                arpsize += arpsize / 8;
        }
        if (st == -1) {
		perror("sysctl");
                return;
	}
}

void *
arplookup_loop(void *unused)
{
	for (;;) {
		fetch_arp();
		sleep(10);
	}
	return 0;
}

void
dns_lookup(struct _estat *s)
{
	struct sockaddr_in sin;
	if (0 == s->ipv4.s_addr)
		return;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = s->ipv4;
	sin.sin_len = sizeof(sin);
	getnameinfo((struct sockaddr *)&sin, sin.sin_len, s->name, sizeof(s->name), 0, 0, NI_NAMEREQD);
	s->name_lookup_time = last;
}

void *
dnslookup_loop(void *unused)
{
	unsigned int i;
	for (;;) {
		for (i = 0; i < nstat; i++) {
			struct _estat *s = Stats_array[i];
			if (last - s->name_lookup_time > 60)
				dns_lookup(s);
		}
		sleep(1);
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc != 2)
		errx(1, "usage: ethertop interface");

	pcap = pcap_open_live(argv[1], 1500, 0, 1, errbuf);
	if (!pcap)
		errx(1, "%s: %s", argv[1], errbuf);

	pthread_mutex_init(&mutex_S, NULL);
	pthread_create(&threadDisplay, NULL, display_loop, NULL);
	pthread_create(&threadArpLookup, NULL, arplookup_loop, NULL);
	pthread_create(&threadDnsLookup, NULL, dnslookup_loop, NULL);

	pcap_loop(pcap, 0, packet, 0);

	pthread_join(threadDisplay, NULL);
	pthread_join(threadArpLookup, NULL);
	pthread_join(threadDnsLookup, NULL);
	endwin();
	return 0;
}
