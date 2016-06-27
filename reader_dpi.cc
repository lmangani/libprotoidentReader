/*
 * libprotoident Reader
 * (c) 2016 QXIP BV
 * see LICENSE for license details
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <map>

#include <libflowmanager.h>
#include <libprotoident.h>
#include <libtrace.h>

#include <signal.h>

volatile sig_atomic_t stop;
void inthand(int signum)
{
    stop = 1;
}


static int total_flows = 0;
static uint64_t total_packets = 0;
static uint64_t total_bytes = 0;
static int wrong_packets = 0;
static int unknown_packets = 0;

char xbuf[32], xbuf1[32];
float tt, bb;

std::map<lpi_module_t*,std::pair<int, int> > known_packets_stat;

int debug = false;
double ts;
double tot_usec;

bool only_dir0 = false;
bool only_dir1 = false;
bool require_both = false;
static volatile int done = 0;


static libtrace_direction_t port_get_direction(libtrace_packet_t *packet, void *l3)
{
  libtrace_direction_t dir = TRACE_DIR_UNKNOWN;
  libtrace_ip_t *ip = NULL;
  uint16_t dst_port;
  uint16_t src_port;
  uint8_t proto;

  src_port = trace_get_source_port(packet);
  dst_port = trace_get_destination_port(packet);

  ip = (libtrace_ip_t *) l3;
  proto = ip->ip_p;

  if (src_port == dst_port) {
    if (ip->ip_src.s_addr < ip->ip_dst.s_addr) {
      dir = TRACE_DIR_OUTGOING;
    } else {
      dir = TRACE_DIR_INCOMING;
    }
  } else {
    if (trace_get_server_port(proto, src_port, dst_port) == USE_SOURCE) {
      dir = TRACE_DIR_OUTGOING;
    } else {
      dir = TRACE_DIR_INCOMING;
    }
  }

  return dir;
}


/* FUNCS Import */

struct ident_stats {
	uint64_t pkts;
	uint64_t bytes;

	uint16_t pktlen_min;
	uint16_t pktlen_max;
	double pktlen_mean;
	double pktlen_std;

	uint32_t iat_min;
	uint32_t iat_max;
	double iat_mean;
	double iat_std;
};

/* This data structure is used to demonstrate how to use the 'extension' 
 * pointer to store custom data for a flow */
typedef struct ident {
	uint8_t init_dir;

	struct ident_stats in;
	struct ident_stats out;

	double start_ts;
	double last_ts;

	lpi_data_t lpi;
} IdentFlow;

void display_ident(Flow *f, IdentFlow *ident)
{
	char s_ip[500];
	char c_ip[500];
	char str[1000];
	lpi_module_t *proto;
	struct ident_stats *is;
	int i;

	if (only_dir0 && ident->init_dir == 1)
		return;
	if (only_dir1 && ident->init_dir == 0)
		return;
	if (require_both) {
		if (ident->lpi.payload_len[0] == 0 ||
		    ident->lpi.payload_len[1] == 0) {
			return;
		}
	}

	proto = lpi_guess_protocol(&ident->lpi);

	f->id.get_server_ip_str(s_ip);
	f->id.get_client_ip_str(c_ip);

	printf("%s %s %s %u %u %u %.3f %" PRIu64 " %" PRIu64 "",
			proto->name, s_ip, c_ip,
                        f->id.get_server_port(), f->id.get_client_port(),
                        f->id.get_protocol(), ident->start_ts,
			ident->out.bytes, ident->in.bytes);


	/* basic statistics */
	/*
	printf("%s,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
		proto->name, f->id.get_protocol(),
		ident->out.pkts, ident->out.bytes, ident->in.pkts, ident->in.bytes);
	*/

	/* print packet length statistics */
	is = &ident->out;
	for (i = 0; i < 2; i++) {
		if (is->pkts == 0) {
			printf(",0,0,0,0");
		} else {
			printf(",%u,%.0f,%u,%.0f",
				is->pktlen_min, is->pktlen_mean, is->pktlen_max,
				(is->pktlen_std / is->pkts));
		}
		is = &ident->in;
	}

	/* print inter-arrival time statistics */
	is = &ident->out;
	for (i = 0; i < 2; i++) {
		if (is->pkts == 0) {
			printf(",0,0,0,0");
		} else {
			printf(",%u,%.0f,%u,%.0f",
				is->iat_min, is->iat_mean, is->iat_max,
				(is->iat_std / is->pkts));
		}
		is = &ident->in;
	}

	/* print total flow duration */
	printf(",%.0f", (ident->last_ts - ident->start_ts) * 1000000.0);

	/* print flow start time */
	printf(",%f", ident->start_ts);

	printf("\n");
}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
void expire_ident_flows(double ts, bool exp_flag)
{
	Flow *expired;
	lpi_module_t *proto;

	/* Loop until libflowmanager has no more expired flows available */
	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {

		IdentFlow *ident = (IdentFlow *)expired->extension;

		// display_ident(expired, ident);
		/* Don't forget to free our custom data structure */
		free(ident);

		/* VERY IMPORTANT: delete the Flow structure itself, even
		 * though we did not directly allocate the memory ourselves */
		delete(expired);
	}
}

/**
 * @brief Traffic stats format
 */
char* formatTraffic(float numBits, int bits, char *buf) {

  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}


/**
 * @brief Packets stats format
 */
char* formatPackets(float numPkts, char *buf) {

  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}


static void process_packet(libtrace_packet_t *packet)
{
  Flow *f = NULL;
  bool is_new = false;
  lpi_data_t *lpi_data = NULL;
  lpi_module_t *protocol = NULL;
  uint16_t l3_type = 0;
  uint8_t dir;
  void *l3 = NULL;

  total_packets++;

  l3 = trace_get_layer3(packet, &l3_type, NULL);
  if (l3_type != TRACE_ETHERTYPE_IP) {
    if (debug) printf("Detected non IPv4 packet; skipping\n");
    wrong_packets++;
    return;
  }

  if (!l3) {
    if (debug) printf("No L3 header found; skipping\n");
    wrong_packets++;
    return;
  }

  // Determine packet direction
  dir = trace_get_direction(packet);
  if (dir != TRACE_DIR_OUTGOING && dir != TRACE_DIR_INCOMING) {
    dir = port_get_direction(packet, l3);
  }

  if (dir != TRACE_DIR_OUTGOING && dir != TRACE_DIR_INCOMING) {
    printf("Unable to detect packet direction; skipping\n");
    unknown_packets++;
    return;
  }

  // Match the packet to a flow. This will create a new flow if there is no
  // matching flow already in the flow map, setting is_new to true
  f = lfm_match_packet_to_flow(packet, dir, &is_new);
  if (!f) {
    if (debug) printf("Can't find the flow for the packet; skipping\n");
    unknown_packets++;
    return;
  }

  // Store the lpi data into the flow
  if (is_new) {
    total_flows++;
    lpi_data = (lpi_data_t *) malloc(sizeof(lpi_data_t));
    lpi_init_data(lpi_data);
    f->extension = lpi_data;
  } else {
    lpi_data = (lpi_data_t *) f->extension;
  }

  // Pass the packet into libprotoident so it can extract any info it needs from
  // this packet
  lpi_update_data(packet, lpi_data, dir);

  // Guess the protocol
  protocol = lpi_guess_protocol(lpi_data);
  if (protocol->protocol != 189 && protocol->protocol != 366) {
    if (debug) printf("%s found! (%d)\n", protocol->name, protocol->protocol);
  }

  if (protocol->protocol == 215) {
	if (debug) printf("Expiring STUN!\n");
	ts = trace_get_seconds(packet);
	lfm_update_flow_expiry_timeout(f, -1);
	expire_ident_flows(ts, false);
	total_flows--;
  }

  int bytes = trace_get_payload_length(packet);
  total_bytes += bytes;

  known_packets_stat[protocol].first++;
  known_packets_stat[protocol].second+=bytes;

}

int main(int argc, char *argv[])
{
  clock_t tStart = clock();
  libtrace_packet_t *packet = NULL;
  libtrace_t *trace = NULL;
  bool opt_false = false;
  bool opt_true = true;
  double ts;
  int result = -1;
  char pcap;

  signal(SIGINT, inthand);

  /* options */
  int opt = 0;
  int limit;
  char *in_fname = NULL;

  while ((opt = getopt(argc, argv, "i:s:h")) != -1) {
     switch(opt) {
      case 'i':
	      in_fname = optarg;
	      break;
      case 's':
	      limit = atoi(optarg);
	      break;
      case '?':
	      /* Case when user enters the command as
	       * $ ./cmd_exe -i
	       */
	      if (optopt == 'i') {
	      	printf("\nMissing mandatory input option");
	      	return -1;

	      /* Case when user enters the command as
	       * # ./cmd_exe -o
	       */
	      } else if (optopt == 'o') {
	       	printf("\nMissing mandatory output option");
	      } else {
	       	printf("\nInvalid option received");
	      }
      	      break;
      case 'h':
		/* print help */
	      printf("-----------------------\n\n");
	      printf("\t -i: \tfilename\tInput PCAP file \n");
	      printf("\t -s: \tinteger \tLimit packets \n");
	      printf("\t -h: \t	\tThis help text \n");
	      printf("\n\n");
	      return -1;
	      break;

    }
  }

  printf("\nlibprotoident Reader 0.1 \n");
  printf("Reading packets from %s ... \t[CTRL-C to stop]\n", in_fname);

  if( ! in_fname ) {
      printf("No filename supplied.\n");
	return -1;
  }


  if (lpi_init_library() < 0) {
    printf("Failed to initialize libprotoident\n");
    return -1;
  }

  /* This tells libflowmanager to ignore any flows where an RFC1918
   * private IP address is involved */
  if (lfm_set_config_option(LFM_CONFIG_IGNORE_RFC1918, &opt_false) == 0)
		return -1;


  // This tells libflowmanager not to replicate the TCP timewait behaviour where
  // closed TCP connections are retained in the Flow map for an extra 2 minutes
  if (lfm_set_config_option(LFM_CONFIG_TCP_TIMEWAIT, &opt_false) == 0) {
    printf("Setting TCP_TIMEWAIT option\n");
    goto error;
  }

  // This tells libflowmanager not to utilise the fast expiry rules for
  // short-lived UDP connections - these rules are experimental behaviour not in
  // line with recommended "best" practice
  if (lfm_set_config_option(LFM_CONFIG_SHORT_UDP, &opt_false) == 0) {
    printf("Setting SHORT_UDP option\n");
    goto error;
  }

  packet = trace_create_packet();
  if (!packet) {
    printf("Creating libtrace packet\n");
    goto error;
  }

  // trace = trace_create(argv[1]);
  trace = trace_create(in_fname);
  if (!trace) {
    printf("Creating libtrace trace\n");
    goto error;
  }

  // Process packet per packet
  if (trace_is_err(trace)) {
    printf("Error Opening trace file\n");
    goto error;
  }

  if (trace_start(trace) < 0) {
    printf("Error Starting trace\n");
    goto error;
  }

  while (trace_read_packet(trace, packet) > 0 && total_packets < limit ) {
    process_packet(packet);
	if (stop) break;
  }

  // Print statistics
  printf("\nDPI Statistics:\n");
  printf("================\n\n");
  printf("\tTOTAL FLOWS: \t\t%d\n", total_flows);
  printf("\tTOTAL BYTES: \t\t%" PRIu64 "\n", total_bytes);
  printf("\tTOTAL PACKETS: \t\t%" PRIu64 "\n", total_packets);
  if (wrong_packets > 0) printf("\tWRONG PACKETS: \t\t%d\n", wrong_packets);
  if (unknown_packets > 0) printf("\tUNKNOWN PACKETS: \t%d\n", unknown_packets);

  	tot_usec = (double)(clock() - tStart)/CLOCKS_PER_SEC*100000;
  	tt = (float)(total_packets*1000000)/(float)tot_usec;
  	bb = (float)(total_bytes * 8 *1000000)/(float)tot_usec;
	printf("\tDPI THROUGHPUT: \t%s pps / %s/sec\n", formatPackets(tt, xbuf), formatTraffic(bb, 1, xbuf1));
	// printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(tt, xbuf), formatTraffic(bb, 1, xbuf1));
	printf("\tTOTAL TIME: \t\t%.3f sec\n", tot_usec/1000000);


  printf("\n\tDetected Protocols:\n");
  printf("\t---------\n");


  /* Print Statistics */
  for (std::map<lpi_module_t*,std::pair<int, int> >::iterator jit = known_packets_stat.begin();
       jit != known_packets_stat.end();
       ++jit) {
    lpi_module_t *p = (lpi_module_t*) jit->first;
	    printf( "\t%-20s", p->name);
	    printf( "PKTS: %-10d", jit->second.first);
	    // printf( "AVG: %-10s ", formatTraffic(jit->second.second/jit->second.first, 1, xbuf1));
	    printf( "TOTAL: %-10s\n", formatTraffic(jit->second.second, 1, xbuf1));
  }

  printf("\n\r");
  result = 0;

 error:
  if (trace) trace_destroy(trace);
  if (packet) trace_destroy_packet(packet);

  if (!done) expire_ident_flows(ts, true);

  lpi_free_library();
  return result;
}
