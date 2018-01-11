#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include "stats.h"
#include "utils.h"

void init_traffic_statistics(struct traffic_stats* stats, time_t current, unsigned long period_between_prints)
{
    memset(stats, 0, sizeof(struct traffic_stats));
    stats->period_between_prints = period_between_prints;

    stats->first_timestamp = current;
    stats->last_timestamp = current;
}

extern ThreadData *thrArr;


void add_tstats(struct traffic_stats_per_thread* t1, struct traffic_stats_per_thread* t2)
{
    t2->tcp_http_request += t1->tcp_http_request;
    t2->tcp_no_http_request += t1->tcp_no_http_request;
    t2->ssl_sni += t1->ssl_sni;
    t2->ssl_no_sni += t1->ssl_no_sni;
    t2->ssl_no_handshake += t1->ssl_no_handshake;
    t2->udp_port1813_not_radius += t1->udp_port1813_not_radius;
    t2->radius_invalid_length += t1->radius_invalid_length;
    t2->radius_invalid_attr_length += t1->radius_invalid_attr_length;
    t2->radius_attribute += t1->radius_attribute;
    t2->radius_irellevant += t1->radius_irellevant;
    t2->radius_location += t1->radius_location;
    t2->radius_login += t1->radius_login;
    t2->radius_logout += t1->radius_logout;
}

void print_traffic_statistics(struct traffic_stats* stats, time_t current, int last, pcap_t* cap)
{
    int cnt;
    ThreadData *td;
    struct traffic_stats_per_thread thr_stats;

    if (last == 0 && current - stats->last_timestamp < stats->period_between_prints)
    {
        return;
    }

    for (cnt = 0; cnt < cfg.threads_num; cnt++)
    {
        td = thrArr + cnt;

        pthread_mutex_lock(&td->stats_mtx);
        memcpy(&thr_stats, &td->t_stats_long, sizeof(thr_stats));
        memset(&td->t_stats_long,0,sizeof(td->t_stats_long));
        pthread_mutex_unlock(&td->stats_mtx);

        stats->tcp_http_request_period += thr_stats.tcp_http_request;
        stats->tcp_http_request_start += thr_stats.tcp_http_request;

        stats->tcp_no_http_request_period += thr_stats.tcp_no_http_request;
        stats->tcp_no_http_request_start += thr_stats.tcp_no_http_request;

        stats->ssl_sni_period += thr_stats.ssl_sni;
        stats->ssl_sni_start += thr_stats.ssl_sni;

        stats->ssl_no_sni_period += thr_stats.ssl_no_sni;
        stats->ssl_no_sni_start += thr_stats.ssl_no_sni;

        stats->ssl_no_handshake_period += thr_stats.ssl_no_handshake;
        stats->ssl_no_handshake_start += thr_stats.ssl_no_handshake;

        stats->udp_port1813_not_radius_period += thr_stats.udp_port1813_not_radius;
        stats->udp_port1813_not_radius_start += thr_stats.udp_port1813_not_radius;

        stats->radius_invalid_length_period += thr_stats.radius_invalid_length;
        stats->radius_invalid_length_start += thr_stats.radius_invalid_length;

        stats->radius_invalid_attr_length_period += thr_stats.radius_invalid_attr_length;
        stats->radius_invalid_attr_length_start += thr_stats.radius_invalid_attr_length;

        stats->radius_attribute_period += thr_stats.radius_attribute;
        stats->radius_attribute_start += thr_stats.radius_attribute;

        stats->radius_irellevant_period += thr_stats.radius_irellevant;
        stats->radius_irellevant_start += thr_stats.radius_irellevant;

        stats->radius_location_period += thr_stats.radius_location;
        stats->radius_location_start += thr_stats.radius_location;

        stats->radius_login_period += thr_stats.radius_login;
        stats->radius_login_start += thr_stats.radius_login;

        stats->radius_logout_period += thr_stats.radius_logout;
        stats->radius_logout_start += thr_stats.radius_logout;
    }


    printf ("==========================================================================\n");
    printf ("Current Time: %s", ctime(&current));
    printf ("==========================================================================\n");
    printf ("                         Traffic Statistics                               \n");
    printf ("==========================================================================\n");
    printf ("Description                      Period               Total               \n");
    printf ("================================ ==================== ====================\n");

    if (cfg.extended_statistics)
    {
        printf ("Ethernet frames:                 %20llu %20llu\n", stats->pkt_count_period, stats->pkt_count_start);
        printf ("Ethernet frames with VLAN:       %20llu %20llu\n", stats->vlan_packet_period, stats->vlan_packet_start);
    }
    printf ("IP Packets:                      %20llu %20llu\n", stats->ip_packet_period, stats->ip_packet_start);
    printf ("Non IP Packets:                  %20llu %20llu\n", stats->non_ip_packet_period, stats->non_ip_packet_start);

    if (cap)
    {
        pcap_stats(cap, &stats->ps_start);
        printf ("PCAP received packets:           %20llu %20llu\n", stats->ps_start.ps_recv - stats->ps_period.ps_recv, stats->ps_start.ps_recv);
        printf ("PCAP dropped packets:            %20llu %20llu\n", stats->ps_start.ps_drop - stats->ps_period.ps_drop, stats->ps_start.ps_drop);
        printf ("PCAP if-dropped packets:         %20llu %20llu\n", stats->ps_start.ps_ifdrop - stats->ps_period.ps_ifdrop, stats->ps_start.ps_ifdrop);
        stats->ps_period = stats->ps_start;
    }
    
    printf ("TCP packets:                     %20llu %20llu\n", stats->tcp_packet_period, stats->tcp_packet_start);
    printf ("TCP parsed packets:              %20llu %20llu\n", stats->tcp_parsed_packets_period, stats->tcp_parsed_packets_start);
    printf ("UDP packets:                     %20llu %20llu\n", stats->udp_packet_period, stats->udp_packet_start);
    printf ("UDP parsed packets:              %20llu %20llu\n", stats->udp_parsed_packets_period, stats->udp_parsed_packets_start);
    printf ("Other IP packets:                %20llu %20llu\n", stats->other_ip_packet_period, stats->other_ip_packet_start);
    if (cfg.extended_statistics)
    {
        printf ("TCP packets without payload:     %20llu %20llu\n", stats->tcp_no_payload_period, stats->tcp_no_payload_start);
        printf ("TCP packet not to 80/443 port:   %20llu %20llu\n", stats->tcp_no_http_period, stats->tcp_no_http_start);
    }
    printf ("Valid HTTP requests              %20llu %20llu\n", stats->tcp_http_request_period, stats->tcp_http_request_start);
    if (cfg.extended_statistics)
    {
        printf ("TCP to 80, not valid request:    %20llu %20llu\n", stats->tcp_no_http_request_period, stats->tcp_no_http_request_start);
        printf ("SSL but not handshake:           %20llu %20llu\n", stats->ssl_no_handshake_period,stats->ssl_no_handshake_start);
        printf ("SSL Handshake without SNI:       %20llu %20llu\n", stats->ssl_no_sni_period,stats->ssl_no_sni_start);
    }
    printf ("SSL Handshake with SNI:          %20llu %20llu\n", stats->ssl_sni_period,stats->ssl_sni_start);
    if (cfg.extended_statistics)
    {
        printf ("UDP no payload:                  %20llu %20llu\n", stats->udp_no_payload_period, stats->udp_no_payload_start);
        printf ("UDP not to port 1813:            %20llu %20llu\n", stats->udp_not_send_port1813_period, stats->udp_not_send_port1813_start);
        printf ("UDP port 1813 not RADIUS acct:   %20llu %20llu\n", stats->udp_port1813_not_radius_period, stats->udp_port1813_not_radius_start);
        printf ("RADIUS invalid length:           %20llu %20llu\n", stats->radius_invalid_length_period, stats->radius_invalid_length_start);
        printf ("RADIUS invalid attr length:      %20llu %20llu\n", stats->radius_invalid_attr_length_period, stats->radius_invalid_attr_length_start);
        printf ("RADIUS attribute processed:      %20llu %20llu\n", stats->radius_attribute_period, stats->radius_attribute_start);
        printf ("RADIUS no info:                  %20llu %20llu\n", stats->radius_irellevant_period, stats->radius_irellevant_start);
        printf ("RADIUS with location:            %20llu %20llu\n", stats->radius_location_period, stats->radius_location_start);
    }
    printf ("RADIUS login/update:             %20llu %20llu\n", stats->radius_login_period, stats->radius_login_start);
    printf ("RADIUS logout:                   %20llu %20llu\n", stats->radius_logout_period, stats->radius_logout_start);
    printf ("Saved UDP packets:               %20llu %20llu\n", stats->processing_saved_udp_packets_period, stats->processing_saved_udp_packets_start);
    printf ("Dropped UDP packets:             %20llu %20llu\n", stats->processing_lost_udp_packets_period, stats->processing_lost_udp_packets_start);
    printf ("Dropped TCP packets:             %20llu %20llu\n", stats->processing_lost_tcp_packets_period, stats->processing_lost_tcp_packets_start);

    fflush(stdout);

    // reset periodic stats
    stats->last_timestamp = current;
    stats->pkt_count_period = 0;
    stats->ip_packet_period = 0;
    stats->vlan_packet_period = 0;
    stats->non_ip_packet_period = 0;
    stats->tcp_packet_period = 0;
    stats->udp_packet_period = 0;
    stats->other_ip_packet_period = 0;
    stats->tcp_no_http_period = 0;
    stats->tcp_http_request_period = 0;
    stats->tcp_no_http_request_period = 0;
    stats->tcp_no_payload_period = 0;
    stats->ssl_no_handshake_period = 0;
    stats->ssl_sni_period = 0;
    stats->ssl_no_sni_period = 0;
    stats->udp_no_payload_period = 0;
    stats->udp_not_send_port1813_period = 0;
    stats->udp_port1813_not_radius_period = 0;
    stats->radius_invalid_length_period = 0;
    stats->radius_invalid_attr_length_period = 0;
    stats->radius_irellevant_period = 0;
    stats->radius_location_period = 0;
    stats->radius_login_period = 0;
    stats->radius_logout_period = 0;
    stats->processing_lost_udp_packets_period = 0;
    stats->processing_lost_tcp_packets_period = 0;
    stats->processing_saved_udp_packets_period = 0;
    stats->tcp_parsed_packets_period = 0;
    stats->udp_parsed_packets_period = 0;
}

void init_subscriber_statistics(struct subscriber_stats* stats, time_t current, unsigned long period_between_prints)
{
    memset(stats, 0, sizeof(struct subscriber_stats));
    stats->period_between_prints = period_between_prints;

    stats->first_timestamp = current;
    stats->last_timestamp = current;
}

void print_subscriber_statistics(struct subscriber_stats* stats, time_t current, int last)
{

    if (last == 0 && current - stats->last_timestamp < stats->period_between_prints)
    {
        return;
    }

    printf ("==========================================================================\n");
    printf ("                        Subscriber Statistics                             \n");
    printf ("==========================================================================\n");
    printf ("Description                      Period               Total               \n");
    printf ("================================ ==================== ====================\n");
    printf ("Subscribers added:               %20llu %20llu\n", stats->subscriber_added_period, stats->subscriber_added_start);
    printf ("Subscribers deleted success:     %20llu %20llu\n", stats->subscriber_deleted_period, stats->subscriber_deleted_start);
    printf ("Subscribers implicit logout:     %20llu %20llu\n", stats->subscriber_implicit_logout_period, stats->subscriber_implicit_logout_start);
    printf ("Subscribers delete failed:       %20llu %20llu\n", stats->subscriber_deleted_failed_period, stats->subscriber_deleted_failed_start);
    printf ("Subscribers already exist:       %20llu %20llu\n", stats->update_no_op_period, stats->update_no_op_start);
    printf ("Subscribers IP lookup failed:    %20llu %20llu\n", stats->http_subscriber_not_found_period, stats->http_subscriber_not_found_start);
    printf ("==========================================================================\n");
    printf ("                          Database Status                                 \n");
    printf ("==========================================================================\n");
    printf ("Total Subscribers: %lu\n", stats->hash_length);
    printf ("Successful Synchs: %lu\n", stats->successful_syncs);
    fflush(stdout);

    // reset periodic stats
    stats->last_timestamp = current;
    stats->subscriber_added_period = 0;
    stats->subscriber_deleted_period = 0;
    stats->subscriber_implicit_logout_period = 0;
    stats->subscriber_deleted_failed_period = 0;
    stats->update_no_op_period = 0;
    stats->http_subscriber_not_found_period = 0;
}

#ifdef COLLECT_CPU_TIMES

void start_measurement(struct rusage* ru)
{
    getrusage(RUSAGE_SELF, ru);
}

void stop_measurement(struct rusage* ruPrev, unsigned long long *count)
{
    struct rusage ruCurr;
    unsigned long long utime, stime;

    getrusage(RUSAGE_SELF, &ruCurr);

    utime = (ruCurr.ru_utime.tv_sec - ruPrev->ru_utime.tv_sec)*1000*1000;
    if (ruCurr.ru_utime.tv_usec >= ruPrev->ru_utime.tv_usec)
        utime += (ruCurr.ru_utime.tv_usec - ruPrev->ru_utime.tv_usec);
    else {
        utime -= 1000*1000;
        utime += (ruPrev->ru_utime.tv_usec - ruCurr.ru_utime.tv_usec);
    }

    stime = (ruCurr.ru_stime.tv_sec - ruPrev->ru_stime.tv_sec)*1000*1000;
    if (ruCurr.ru_stime.tv_usec >= ruPrev->ru_stime.tv_usec)
        stime += (ruCurr.ru_stime.tv_usec - ruPrev->ru_stime.tv_usec);
    else {
        stime -= 1000*1000;
        stime += (ruPrev->ru_stime.tv_usec - ruCurr.ru_stime.tv_usec);
    }

    *count += utime + stime;
}

#endif /* #ifdef COLLECT_CPU_TIMES */
