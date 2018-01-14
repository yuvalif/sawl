#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>  /* getopt() */
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>

#include "trace.h"
#include "packet.h"
#include "http.h"
#include "radius.h"
#include "subscriber_db.h"

#include "utils.h"

HttpSnifferCfg cfg;
ThreadData *thrArr;

struct traffic_stats t_stats;
struct subscriber_stats subscr_stats;

void init_cfg()
{
    memset(&cfg,0,sizeof(cfg));

    cfg.url_len = DEFAULT_URL_LEN;
    cfg.period = DEFAULT_PERIOD;
    cfg.redis_port = DEFAULT_REDIS_PORT;
    cfg.snap_len = DEFAULT_SNAP_LEN;
    cfg.period_between_prints = DEFAULT_PRINT;

    cfg.threads_num = DEFAULT_THREADS_NUM;
    cfg.packets_per_bucket = DEFAULT_PACKS_PER_BUCKET;

#ifndef NOLOGS
    cfg.debug_level = LOG_FATAL;
#endif
}
    
/**
 * Help function to print usage information.
 */
void
print_usage(const char* pro_name)
{
    printf("Usage: %s [-i interface | -f tracefile] \n\
          [-r redis_host[:port]]  \n\
          [-d debug_level (1-5)]  \n\
          [-p CSV rotation period (seconds)]  \n\
          [-s snap length (bytes)]  \n\
          [-t stats period (seconds)] \n\
          [-e extended statistics] \n\
          [-u URL length (bytes)]  \n\
          [-l for SLL/SNI]  \n\
          [-w workers threads number]  \n\
          [-b thread bucket size]  \n\
          [-o do not perform TCP/UDP processing]\n\
          [-v print version and exit]\n",
            pro_name);
}

void
print_version(const char* pro_name)
{
#ifdef VERSION 
    const char* version = VERSION;
#else
    const char* version = "Undefined version";
#endif
    printf("%s version is %s \n",pro_name,version);
}

void add_packet_to_current_thread(const char* p, int len, int isUdp);

void add_packet_to_all_threads(const char* p, int len);

#define PACKET_PROCESS_FAIL -1
#define PACKET_PROCESS_OK 0

int
packet_process_tcp(ThreadData* td, const char* tcp_packet,
        const char* saddr, const char* daddr, u_int16_t dport, u_int16_t tcp_dl)
{
    int retV = PACKET_PROCESS_OK;
    const char* cp = tcp_packet;

    if (dport == 443)
    {
        char host[HOST_NAME_MAX_LEN];
        int retv,isHelloMessage=0;
        retv = ssl_find_host_name(cp, tcp_dl, host, HOST_NAME_MAX_LEN, &isHelloMessage);
        if (retv < 0)
        {
            if (isHelloMessage)
                td->t_stats_short.ssl_no_sni++;
            else 
                td->t_stats_short.ssl_no_handshake++;
            return PACKET_PROCESS_FAIL;
        }
        td->t_stats_short.ssl_sni++;
        LOG(LOG_INFO, "SSL handshake with server-name-extension at packet %llu %s->%s has host %s\n", t_stats.pkt_count_start, saddr, daddr, host);
        if (cfg.url_len == 0)
            set_host_to_db(td, saddr, host);
        else
            set_url_to_db(td, saddr,"",host);
        return PACKET_PROCESS_OK;
    }
    else if (dport != 80)
    {
        // can't be here
        return PACKET_PROCESS_FAIL;
    }

    /* Process packets of flows which carry HTTP traffic */
    {
        char* h, *u;
        int   hLen, uLen, r;
        char  hst[HOST_NAME_MAX_LEN];

        r = http_process((char*)cp,tcp_dl,&h,&hLen,(cfg.url_len > 0)?&u:NULL,&uLen);

        if (r < 0)
            // http_process says this is not valid HTTP request packet
            td->t_stats_short.tcp_no_http_request++;
        else {
            // it is valid HTTP request
            td->t_stats_short.tcp_http_request ++;


            if (h && hLen < HOST_NAME_MAX_LEN-1)
            {
                // the url and host may overlap in the last byte and these
                // two may be used together and both need to be zero terminated strings
                // thus I copy the host (it's generally shorter) to a separate buffer
                // TODO: the http_process may tell us whether url and host do overlap
                // and thus this copy may be prevented in most situations
                // or set_host_to_db & set_url_to_db may be modified to handle pointer and length
                // and not zero terminated strings

                memcpy(hst,h,hLen);
                hst[hLen] = 0;


                if (u && uLen >= cfg.url_len)
                    uLen = cfg.url_len - 1;

                if (u && uLen < cfg.url_len) {
                    char c = u[uLen];
                    u[uLen] = 0;
                    set_url_to_db(td, saddr,u,hst);
                    u[uLen] = c;
                }
                else {
                    set_host_to_db(td, saddr,hst);
                }
            }
        }


        retV = (h) ? PACKET_PROCESS_OK: PACKET_PROCESS_FAIL;
    }

    return retV;
}

int
packet_process_udp(ThreadData* td, const char* udp_packet, const char* saddr, const char* daddr)
{
    const char* cp = udp_packet;
    udphdr* udp_hdr = (udphdr*)udp_packet;
    u_int16_t udp_dl = ntohs(udp_hdr->uh_length);
    struct radius_hdr* radhdr;
    u_int16_t rad_dl;
    int radius_bytes_left;
    struct radius_info info;

    cp += sizeof(udphdr);
    radhdr = (struct radius_hdr*)cp;
    /* verify accounting request message */
    if (radhdr->code != RADIUS_ACCT_REQUEST)
    {
        if (td->is_first_thread)
        {
            td->t_stats_short.udp_port1813_not_radius++;
            LOG(LOG_WARN, "Not a RADIUS accounting request packet to RADIUS accounting port %llu %s->%s\n", t_stats.pkt_count_start, saddr, daddr);
        }
        return PACKET_PROCESS_FAIL;
    }
    rad_dl = ntohs(radhdr->len);
    /* verify valid length */
    if (udp_dl != rad_dl + sizeof(udphdr))
    {
        if (td->is_first_thread)
        {
            td->t_stats_short.radius_invalid_length++;
            LOG(LOG_ERR, "RADIUS length does not match UDP length in packet %llu %s->%s\n", t_stats.pkt_count_start, saddr, daddr);
        }
        return PACKET_PROCESS_FAIL;
    }

    cp += sizeof(struct radius_hdr);
    radius_bytes_left = rad_dl - sizeof(struct radius_hdr);
    memset(&info, 0, sizeof(struct radius_info));
    while(radius_bytes_left > 0)
    {
        /* parse RADIUS attributes*/
        struct radius_attr* ra = (struct radius_attr*)cp;
        if (ra->len == 0)
        {
            if (td->is_first_thread)
            {
                td->t_stats_short.radius_invalid_attr_length++;
                LOG(LOG_ERR, "RADIUS AVP of length zero in packet %llu %s->%s\n", t_stats.pkt_count_start, saddr, daddr);
            }
            return PACKET_PROCESS_FAIL;
        }
        if (td->is_first_thread)
        {
            td->t_stats_short.radius_attribute++;
            LOG(LOG_DBG, "RADIUS AVP of type %d in packet %llu %s->%s\n", ra->type, t_stats.pkt_count_start, saddr, daddr);
        }
        append_radius_info(ra, &info);

        /* if all info is extracted or type is terminate, no need to continue*/
        if (info._has_ip && info._has_name && info._location_update &&
                (info._logout || info._login_or_update))
        {

            break;
        }
        cp += ra->len;
        radius_bytes_left -= ra->len;
    }

    /* if info has name and IP and then store info*/
    if (info._has_ip && info._has_name)
    {
        if (info._location_update)
        {
            if (td->is_first_thread)
            {
                td->t_stats_short.radius_location++;
                /* location updates*/
                set_location_to_db(td, info._ip, info._name, info._cell_id);
            }
            if (info._logout)
            {
                if (td->is_first_thread)
                    td->t_stats_short.radius_logout++;
                /* may get location update on logout*/
                del_from_db(td, info._ip);
            }
            else
            {
                /* update or login with location*/
                if (td->is_first_thread)
                    td->t_stats_short.radius_login++;
                set_to_db(td, info._ip, info._name);
            }
        }
        else if (info._login_or_update)
        {
            if (td->is_first_thread)
                td->t_stats_short.radius_login++;
            /* update or login without location*/
            set_to_db(td, info._ip, info._name);
        }
        else if (info._logout)
        {
            if (td->is_first_thread)
                td->t_stats_short.radius_logout++;
            /* logout */
            del_from_db(td, info._ip);
        }
        else
        {
            assert(0);
        }
    }
    else if (td->is_first_thread)

    {
        td->t_stats_short.radius_irellevant++;
        LOG(LOG_WARN, "No relevant info found in RADIUS packet %llu %s->%s\n", t_stats.pkt_count_start, saddr, daddr);
    }

    return PACKET_PROCESS_OK;
}

/**
 * Parse packets' information
 */
int
packet_process(const char* raw_data, const struct pcap_pkthdr* pkthdr)
{
    const char* cp = raw_data;
    ethhdr* eth_hdr;
    iphdr*  ip_hdr;
    vlhdr* vl_hdr;
    u_int8_t ip_hl, tcp_hl, udp_hl;
    unsigned short dport, tcp_dl, udp_dl, ip_offs;


    t_stats.pkt_count_start++;
    t_stats.pkt_count_period++;

    /* Parse ethernet header and check IP payload */
    eth_hdr = (ethhdr*)cp;
    /* check for 802.1q VLAN tags */
    switch (ntohs(eth_hdr->ether_type))
    {
        case ETHERTYPE_IP:
            ip_offs = sizeof(ethhdr);
            cp += sizeof(ethhdr);
            break;
        case ETHERTYPE_VLAN:
            vl_hdr = (vlhdr*)cp;
            if (ntohs(vl_hdr->ether_type) != ETHERTYPE_IP)
            {
                t_stats.non_ip_packet_start++;
                t_stats.non_ip_packet_period++;
                LOG(LOG_DBG, "Non IP type 0x%x after VLAN at packet %llu\n", ntohs(vl_hdr->ether_type), t_stats.pkt_count_start);
                return PACKET_PROCESS_FAIL;
            }
            t_stats.vlan_packet_start++;
            t_stats.vlan_packet_period++;
            ip_offs = sizeof(vlhdr);
            cp += sizeof(vlhdr);
            break;
        default:
            t_stats.non_ip_packet_start++;
            t_stats.non_ip_packet_period++;
            LOG(LOG_DBG, "Non IP/VLAN type 0x%x at packet %llu\n", ntohs(eth_hdr->ether_type), t_stats.pkt_count_start);
            return PACKET_PROCESS_FAIL;
    }

    t_stats.ip_packet_start++;
    t_stats.ip_packet_period++;

    /* Parse IP header and check TCP payload */
    ip_hdr = (iphdr*)cp;
    /* TODO: exclude IPv6 packets */
    ip_hl = (ip_hdr->ihl) << 2; /* bytes */

    switch (ip_hdr->protocol)
    {
        case TCP_PRO:

            t_stats.tcp_packet_start++;
            t_stats.tcp_packet_period++;

            if (cfg.only_ip_processing)
                return PACKET_PROCESS_FAIL;

            cp += ip_hl;
            tcp_hl = (((tcphdr*)cp)->th_off) << 2;   // TCP header length
            tcp_dl = ntohs(ip_hdr->tot_len) - ip_hl - tcp_hl;  // TCP payload  

            if (tcp_dl == 0)
            {
                t_stats.tcp_no_payload_start++;
                t_stats.tcp_no_payload_period++;
                return PACKET_PROCESS_FAIL;
            }

            dport = ntohs(((tcphdr*)cp)->th_dport);

            if (dport != 80 && (dport != 443 || !cfg.ssl_sni_enabled))
            {
                t_stats.tcp_no_http_start++;
                t_stats.tcp_no_http_period++;
                return PACKET_PROCESS_FAIL;
            }

            t_stats.tcp_parsed_packets_start ++;
            t_stats.tcp_parsed_packets_period ++;

            {
                int l;
                // calculate the packet length
                // it is built of offset before the IP (ethernet or vlan) 
                // ip-header-length, tcp-header-length and tcp payload length
                l = ip_offs + ip_hl + tcp_hl + tcp_dl;

                // if the total is bigger than snap-len
                // we must remove limit ourself to snap-len
                if (l > cfg.snap_len)
                    l = cfg.snap_len;

                // then we remove the offset before IP header
                l -= ip_offs;

                // cp points to start of IP header
                cp = raw_data + ip_offs;
                add_packet_to_current_thread(cp, l, 0);
            }

            return PACKET_PROCESS_OK;
        case UDP_PRO:
            t_stats.udp_packet_start++;
            t_stats.udp_packet_period++;

            if (cfg.only_ip_processing)
                return PACKET_PROCESS_FAIL;
            udp_hl = sizeof(udphdr);
            cp += ip_hl;
            udp_dl = ntohs(((udphdr*)cp)->uh_length) - udp_hl;

            if (udp_dl == 0)
            {
                t_stats.udp_no_payload_start++;
                t_stats.udp_no_payload_period++;
                return PACKET_PROCESS_FAIL;
            }

            dport = ntohs(((udphdr*)cp)->uh_dport);

            if (dport != 1813)
            {
                t_stats.udp_not_send_port1813_start++;
                t_stats.udp_not_send_port1813_period++;
                return PACKET_PROCESS_FAIL;
            }


            t_stats.udp_parsed_packets_start ++;
            t_stats.udp_parsed_packets_period ++;

            {
                int l;
                // see the explanations above in TCP case
                l = ip_offs + ip_hl + udp_hl + udp_dl;

                if (l > cfg.snap_len)
                    l = cfg.snap_len;

                l -= ip_offs;

                // cp points to start of IP header
                cp = raw_data + ip_offs;

                add_packet_to_all_threads(cp, l);
            }
            return PACKET_PROCESS_OK;
            //return packet_process_udp(cp, saddr, daddr);
        default:
            t_stats.other_ip_packet_start++;
            t_stats.other_ip_packet_period++;
            LOG(LOG_DBG, "Non TCP/UDP type %d at packet %llu \n", ip_hdr->protocol, t_stats.pkt_count_start);
            return PACKET_PROCESS_FAIL;
    }
    assert(0);
}

#define USE_FILE 0
#define USE_INTERFACE 1
#define LAST 1
#define NOT_LAST 0

/**
 * Main capture function
 */

pcap_t *cap = NULL;


void packet_handler(u_char *user, const struct pcap_pkthdr *h,
                     const u_char *bytes)
{
    static int packCnt = 0;

    if( NULL != bytes)
    {
        packCnt++;
        packet_process((char*)bytes, h);
    }


    if (packCnt >= 100)
    {
        time_t current;
        packCnt = 0;
        time(&current);
        print_traffic_statistics(&t_stats, current, NOT_LAST,(cfg.mode == USE_INTERFACE)?cap:NULL);
        print_subscriber_statistics(&subscr_stats, current, NOT_LAST);
    }

}

void wake_up_all_threads(int finish);
int all_threads_finished();

/*TODO: change function header to read configuration object from inside*/
int
capture_main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    time_t current;
    int retV;
    const int PROCESS_ALL_PACKETS = 0;

    if (cfg.mode == USE_INTERFACE)
    {
        cap = pcap_open_live(cfg.interface, cfg.snap_len, 1, 1000, errbuf);
    }
    else
    {
        cap = pcap_open_offline(cfg.tracefile, errbuf);
    }

    if(cap == NULL)
    {
        LOG(LOG_FATAL, "%s\n",errbuf);
        exit(1);
    }

    /*TODO: break loop on SIGINT*/
    /*TODO: reload configuration on SIGUSR1 */

    retV = pcap_loop(cap, PROCESS_ALL_PACKETS, packet_handler, NULL);

    if (retV == 0)
    {
        LOG(LOG_INFO, "pcap finished processing\n");
    }
    else if (retV == -1)
    {
        LOG(LOG_INFO, "pcap terminated on signal\n");
    }
    else
    {
        LOG(LOG_FATAL, "pcap terminated on error\n");
    }

    if(cap != NULL)
    {
        pcap_close(cap);
    }

    if (cfg.mode == USE_FILE)
    {
        wake_up_all_threads(1);

        while (1)
        {
            sleep(1);
            if (all_threads_finished())
                break;
        }
    }

    // force printing at the end
    time(&current);

    print_traffic_statistics(&t_stats, current, LAST,(cfg.mode == USE_INTERFACE)?cap:NULL);
    print_subscriber_statistics(&subscr_stats, current, LAST);
    return 0;
}

void constr_packets(packets* p, int sz)
{
    int cnt;

    p->packs_sz = sz;
    p->packs = (char**) malloc(sizeof(char*) * sz);
    assert(p->packs);

    p->pack_lens = (int*) malloc(sizeof(int) * sz);
    assert(p->pack_lens);

    for (cnt = 0; cnt < sz; cnt++)
    {
        p->packs[cnt] = (char*) malloc(cfg.snap_len);
        assert(p->packs[cnt]);
    }
    p->packs_saved = 0;

}

void init_packets(ThreadData *td)
{
    td->packs_processed = 0;

    constr_packets(&td->p, cfg.packets_per_bucket);
    constr_packets(&td->udp_p, DEFAULT_UDP_PACKETS);
    pthread_mutex_init(&td->udp_p_mtx, NULL);

}

void* thr_routine(void* _ptr)
{
    size_t thrIndex = (size_t) _ptr;
    ThreadData* td = thrArr + thrIndex;
    int cnt,l;    
    const char* cp;
    iphdr*  ip_hdr;
    u_int8_t ip_hl;
    unsigned short dport, tcp_hl;
    struct in_addr tmp_addr;
    char saddr[16];
    char daddr[16];
    time_t start;

    sem_init(&td->sema,0,0);
    pthread_mutex_init(&td->stats_mtx, NULL);

    if (td->t_index == 1)
    {
        td->is_first_thread = 1;
    }

    init_db(td);

    time(&start);
    printf("thread %d started: %s\n", td->t_index, ctime(&start));

    td->is_up = 1; 
    td->filled_up = 1;

again:
    sem_wait(&td->sema);

    for (cnt = 0; cnt < td->p.packs_saved; cnt ++)
    {
        cp = td->p.packs[cnt];
        l = td->p.pack_lens[cnt];

        ip_hdr = (iphdr*)cp;
        /* TODO: exclude IPv6 packets */
        ip_hl = (ip_hdr->ihl) << 2; /* bytes */

        tmp_addr.s_addr = ip_hdr->saddr;
        strncpy(saddr, inet_ntoa(tmp_addr), 16);
        tmp_addr.s_addr = ip_hdr->daddr;
        strncpy(daddr, inet_ntoa(tmp_addr), 16);

        cp += ip_hl;

        if (ip_hdr->protocol == TCP_PRO)
        {
            dport = ntohs(((tcphdr*)cp)->th_dport);
            tcp_hl = (((tcphdr*)cp)->th_off) << 2;
            cp += tcp_hl;
            l -= ip_hl;
            l -= tcp_hl;
            packet_process_tcp(td, cp, saddr, daddr, dport, l);
        }
        else if (ip_hdr->protocol == UDP_PRO)
        {
            packet_process_udp(td, cp,saddr,daddr);
        }
        else 
        {
            // can't be here
        }

#define STATS_SHORT_TO_LONG_EVERY  1000
        td->statsUpdateCnt ++;
        if (td->statsUpdateCnt == STATS_SHORT_TO_LONG_EVERY)
        {
            td->statsUpdateCnt = 0;
            pthread_mutex_lock(&td->stats_mtx);
            add_tstats(&td->t_stats_short, &td->t_stats_long);
            memset(&td->t_stats_short,0,sizeof(td->t_stats_short));
            pthread_mutex_unlock(&td->stats_mtx);

        }

        td->packs_processed ++;
    }

    pthread_mutex_lock(&td->udp_p_mtx);

    if (td->udp_p.packs_saved)
    {
        // move all this packets to regular bucket
        char *b;
        for (cnt = 0; cnt < td->udp_p.packs_saved; cnt++)
        {
            b = td->p.packs[cnt];
            td->p.packs[cnt] = td->udp_p.packs[cnt];
            td->udp_p.packs[cnt] = b;
            td->p.pack_lens[cnt] = td->udp_p.pack_lens[cnt];
        }
        td->p.packs_saved = td->udp_p.packs_saved;
        td->udp_p.packs_saved = 0;
    }
    pthread_mutex_unlock(&td->udp_p_mtx);

    td->is_processing = 0;

    if (!td->needToFinish)
    {
        goto again;
    }

    close_db(td);

    td->hasFinished = 1;

    return _ptr;
}

/**
 * Main portal of http-sniffer
 */

int main(int argc, char *argv[])
{
    int opt, cnt;
    time_t start,end;

    init_cfg();

    /* Parse arguments */
    while((opt = getopt(argc, argv, "hvelou:t:i:f:r:d:p:s:w:b:")) != -1)
    {
        switch(opt)
        {
        case 'v':
            print_version(argv[0]); return (0);
        case 'h':
            print_usage(argv[0]); return (0);
        case 'e':
            cfg.extended_statistics = 1; break;
        case 'i':
            strcpy(cfg.interface,optarg); break;
        case 'f':
            strcpy(cfg.tracefile,optarg); break;
        case 't':
            cfg.period_between_prints = strtoul(optarg, NULL, 0);
            if (cfg.period_between_prints == 0) cfg.period_between_prints = DEFAULT_PRINT;
            break;
        case 'w':
            cfg.threads_num = strtoul(optarg, NULL, 0);
            if (cfg.threads_num <= 0 || cfg.threads_num > 100) cfg.threads_num = DEFAULT_THREADS_NUM;
            break;
        case 'b':
            cfg.packets_per_bucket = strtoul(optarg, NULL, 0);
            break;
        case 'r':
            {
                int items = sscanf(optarg, "%[^:]:%hu", cfg.redis_host, &cfg.redis_port);
                if (items == 0) cfg.redis_host[0] = 0;
                if (items == 1) cfg.redis_port = DEFAULT_REDIS_PORT;
            }
            break;
        case 'd':
#ifdef NOLOGS
            printf("*********************** Application has been compiled in NOLOGs mode\n");
#else
            cfg.debug_level = strtoul(optarg, NULL, 0);
            if (cfg.debug_level > LOG_DBG || cfg.debug_level < LOG_FATAL)
                cfg.debug_level = LOG_FATAL;
#endif
            break;
        case 'p':
            cfg.period = strtoul(optarg, NULL, 0);
            if (cfg.period == 0) cfg.period = DEFAULT_PERIOD;
            break;
        case 's':
            cfg.snap_len = strtoul(optarg, NULL, 0);
            if (cfg.snap_len == 0) cfg.snap_len = DEFAULT_SNAP_LEN;
            break;
        case 'u':
            cfg.url_len = strtoul(optarg, NULL, 0);
            break;
        case 'l':
            cfg.ssl_sni_enabled = 1;
            break;
        case 'o':
            cfg.only_ip_processing = 1;
            break;
        default:
            print_usage(argv[0]); return (1);
        }
    }

    /* Check interfaces */
    if ((cfg.interface[0] == 0 && cfg.tracefile[0] == 0))
    {
        LOG(LOG_FATAL, "Either interface of tracefile must be provided\n");
        return (1);
    }
    else if (cfg.interface[0] != 0 && cfg.tracefile[0] != 0) {
        LOG(LOG_FATAL, "Both interface and tracefile are provided\n");
        return (1);
    }

    time(&start);
    printf("HTTP/RADIUS (%s) sniffer started: %s\n", VERSION, ctime(&start));
    printf("Configuration: \n");
    printf("       number of threads     : %lu\n", cfg.threads_num);
    printf("       thread bucket size    : %lu packets\n", cfg.packets_per_bucket);
    printf("       URL size              : %u bytes\n", cfg.url_len);
    printf("       support SSL           : %d\n", cfg.ssl_sni_enabled);
    printf("       snap len              : %lu bytes\n", cfg.snap_len);
    printf("       file rotation period  : %lu seconds\n", cfg.period);
    printf("       connect to REDIS      : %s:%u\n", cfg.redis_host, cfg.redis_port);
    printf("       read from interface   : %s\n", cfg.interface);
    printf("       read from file        : %s\n", cfg.tracefile);
    printf("       log period            : %lu seconds\n", cfg.period_between_prints);

    init_traffic_statistics(&t_stats, start, cfg.period_between_prints);
    init_subscriber_statistics(&subscr_stats, start, cfg.period_between_prints);

    {
        struct stat st;
        if (stat("./output",&st))
            mkdir("./output",0777);
    }


    thrArr = (ThreadData*) malloc(sizeof(ThreadData)*cfg.threads_num);
    memset(thrArr,0,sizeof(ThreadData)*cfg.threads_num);
    for (cnt = 0; cnt < cfg.threads_num; cnt++)
    {
        thrArr[cnt].t_index = cnt + 1;
        init_packets(&(thrArr[cnt]));
        pthread_create(&(thrArr[cnt].thr),NULL,thr_routine,(void*)((size_t)cnt));
    }

    while (1)
    {
        for (cnt = 0; cnt < cfg.threads_num; cnt ++)
        {
            if (!thrArr[cnt].is_up)
                break;
        }
        if (cnt == cfg.threads_num)
            break;
        sleep(1);
    }

    printf("All threads are up\n");

    /* start capture in live or offline mode */
    if (cfg.interface[0] != 0)
    {
        cfg.mode = USE_INTERFACE;
        capture_main();
    }
    else
    {
        cfg.mode = USE_FILE;
        capture_main();
    }

    time(&end);
    printf("HTTP/RADIUS sniffer ended. Time elapsed: %d s\n", (int)(end - start));
    return (0);
}

// returns 0, if the bucket was not yet filled up;
// 1 if was filled up
int add_packet_to_queue(const char* p, int len, ThreadData* td, int isUdp)
{
    int S = cfg.packets_per_bucket;
    char *dst;
 
    if (td->is_processing)
    {
        // the current thread has not completed to perform its bucket processing
        // have to drop the packet
        if (isUdp)
        {
            if (td->udp_p.packs_saved == DEFAULT_UDP_PACKETS)
            {
                t_stats.processing_lost_udp_packets_start ++;
                t_stats.processing_lost_udp_packets_period ++;
            }
            else {
                t_stats.processing_saved_udp_packets_start ++;
                t_stats.processing_saved_udp_packets_period ++;

                pthread_mutex_lock(&td->udp_p_mtx);
                dst = td->udp_p.packs[td->udp_p.packs_saved];
                // add this packet to the current thread
                memcpy(dst, p, len);
                td->udp_p.pack_lens[td->udp_p.packs_saved] = len;
                td->udp_p.packs_saved ++;
                pthread_mutex_unlock(&td->udp_p_mtx);
            }

        }
        else {
            t_stats.processing_lost_tcp_packets_start ++;
            t_stats.processing_lost_tcp_packets_period ++;
        }
        return 0;
    }

    // we know: the thread 'td' is idle now, that is, it is sleeping on the semaphore
    if (td->filled_up)
    {
        td->p.packs_saved = 0;
        td->filled_up = 0;
    }

    dst = td->p.packs[td->p.packs_saved];
    // add this packet to the current thread
    memcpy(dst, p, len);
    td->p.pack_lens[td->p.packs_saved] = len;
    td->p.packs_saved ++;

    if (td->p.packs_saved == S)
    {
        // this bucket gets  full
        td->is_processing = 1;
        td->packs_processed = 0;

        td->filled_up = 1;

        // wake up the working thread
        sem_post(&td->sema);

        // return 1: means this thread's bucket is full
        return 1;    
    }
    else 
        // the bucket is not yet full
        return 0;
}

static int  currentThrInd = 0;

void add_packet_to_current_thread(const char* p, int len, int isUdp)
{
    ThreadData *td = thrArr + currentThrInd;
    int ret;

    ret = add_packet_to_queue(p, len, td, isUdp);

    if (ret)
    {
        // this (referred by currentThrInd) bucket was filled up
        // have to move to the next thread
        currentThrInd ++;
        if (currentThrInd == cfg.threads_num)
            currentThrInd = 0;
    }
}

void add_packet_to_all_threads(const char* p, int len)
{
    int cnt, ret, sz = cfg.threads_num;
    int currThrNeedsToChange = 0;

    for (cnt = 0; cnt < sz; cnt ++)
    {
        ret = add_packet_to_queue(p, len, thrArr + cnt, 1);
        if (ret && cnt == currentThrInd)
            // thread that is defined was filled up
            // thus we need to find other thread to set as current
            currThrNeedsToChange = 1;
    }

    if (currThrNeedsToChange)
    {
        for (cnt = 0; cnt < sz; cnt ++)
        {
            if (!thrArr[cnt].is_processing)
            {
                currentThrInd = cnt;
                break;
            }
        }

        if (cnt == sz)
        {
            // BAD BAD BAD 
            // all threads' buckets are full
            // we will be loosing packets
            // no matter what is the current thread
            // let's say it'll be the first one
            currentThrInd = 0;
    }
}
}

void wake_up_all_threads(int finish)
{
    ThreadData *td;
    int cnt;

    for (cnt = 0; cnt < cfg.threads_num; cnt ++)
    {
        td = thrArr + cnt;
        td->is_processing = 1;
        td->packs_processed = 0;
        td->needToFinish = finish;
        sem_post(&td->sema);
    }
}

int all_threads_finished()
{
    ThreadData *td;
    int cnt;

    for (cnt = 0; cnt < cfg.threads_num; cnt ++)
    {
        td = thrArr + cnt;
        if (!td->hasFinished)
            return 0;
    }
    return 1;
}
