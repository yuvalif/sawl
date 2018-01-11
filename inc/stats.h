#ifndef _STATS_H_
#define _STATS_H_

#include <time.h>
#include <sys/resource.h>
#include <pcap/pcap.h>

//#define COLLECT_CPU_TIMES

struct traffic_stats_per_thread
{
    unsigned long long  tcp_http_request;
    unsigned long long  tcp_no_http_request;
    unsigned long long  ssl_sni;
    unsigned long long  ssl_no_sni;
    unsigned long long  ssl_no_handshake;
    unsigned long long  udp_port1813_not_radius;
    unsigned long long  radius_invalid_length;
    unsigned long long  radius_invalid_attr_length;
    unsigned long long  radius_attribute;
    unsigned long long  radius_irellevant;
    unsigned long long  radius_location;
    unsigned long long  radius_login;
    unsigned long long  radius_logout;
};

void add_tstats(struct traffic_stats_per_thread* t1, struct traffic_stats_per_thread* t2);

struct traffic_stats
{
    /** timestamp for last period **/
    time_t              first_timestamp; /* unix time in seconds */
    time_t              last_timestamp; /* unix time in seconds */
    unsigned long       period_between_prints; /* in seconds */

    /** pcap counters **/
    unsigned long long  pkt_count_start;
    unsigned long long  pkt_count_period;

    /** how many IP non-IP packets were observed */
    unsigned long long  vlan_packet_start;
    unsigned long long  vlan_packet_period;
    unsigned long long  ip_packet_start;
    unsigned long long  ip_packet_period;
    unsigned long long  non_ip_packet_start;
    unsigned long long  non_ip_packet_period;

    /** how many UDP, TCP and other IP packets were observed*/
    unsigned long long  tcp_packet_start;
    unsigned long long  tcp_packet_period;
    unsigned long long  udp_packet_start;
    unsigned long long  udp_packet_period;
    unsigned long long  other_ip_packet_start;
    unsigned long long  other_ip_packet_period;

    /** how many TCP packets without payload were observed*/
    unsigned long long  tcp_no_payload_start;
    unsigned long long  tcp_no_payload_period;

    /** how many TCP/UDP packets were parsed for HTTP/SSL (TCP) and RADIUS (UDP) */
    unsigned long long  tcp_parsed_packets_start;
    unsigned long long  tcp_parsed_packets_period;
    unsigned long long  udp_parsed_packets_start;
    unsigned long long  udp_parsed_packets_period;

    /** how many UDP packets without payload were observed*/
    unsigned long long  udp_no_payload_start;
    unsigned long long  udp_no_payload_period;

    /** how many TCP packets not destined to port 80/443 were observed (only packets with payload are counted) */
    unsigned long long  tcp_no_http_start;
    unsigned long long  tcp_no_http_period;

    /** how many TCP packets destined to port 80 are valid HTTP requests*/
    unsigned long long  tcp_http_request_start;
    unsigned long long  tcp_http_request_period;

    /** how many TCP packets destined to port 80 are valid HTTP requests*/
    unsigned long long  tcp_no_http_request_start;
    unsigned long long  tcp_no_http_request_period;

    /** SSL client-handshake containing server-name extension*/
    unsigned long long ssl_sni_start;
    unsigned long long ssl_sni_period;

    /** SSL client-handshake not containing server-name extension*/
    unsigned long long ssl_no_sni_start;
    unsigned long long ssl_no_sni_period;

    /** TCP packets destined to 443 port that are not client-handshake*/
    unsigned long long ssl_no_handshake_start;
    unsigned long long ssl_no_handshake_period;


    /** how many UDP not sent to port 1813*/
    unsigned long long  udp_not_send_port1813_start;
    unsigned long long  udp_not_send_port1813_period;

    /** how many UDP packets sent to 1813 are not of type RADIUS accounting*/
    unsigned long long  udp_port1813_not_radius_start;
    unsigned long long  udp_port1813_not_radius_period;

    /** how many RADIUS packets have invalid length. and how many has invalid attribute length*/
    unsigned long long  radius_invalid_length_start;
    unsigned long long  radius_invalid_length_period;
    unsigned long long  radius_invalid_attr_length_start;
    unsigned long long  radius_invalid_attr_length_period;
    unsigned long long  radius_attribute_start;
    unsigned long long  radius_attribute_period;;

    unsigned long long  radius_irellevant_start;
    unsigned long long  radius_irellevant_period;

    unsigned long long  radius_location_start;
    unsigned long long  radius_location_period;

    unsigned long long  radius_login_start;
    unsigned long long  radius_login_period;

    unsigned long long  radius_logout_start;
    unsigned long long  radius_logout_period;

    struct pcap_stat    ps_start;
    struct pcap_stat    ps_period;

    unsigned long long  processing_saved_udp_packets_start;
    unsigned long long  processing_saved_udp_packets_period;

    unsigned long long  processing_lost_udp_packets_start;
    unsigned long long  processing_lost_udp_packets_period;

    unsigned long long  processing_lost_tcp_packets_start;
    unsigned long long  processing_lost_tcp_packets_period;
};




extern void print_traffic_statistics(struct traffic_stats* stats, time_t current, int last, pcap_t* cap);
extern void init_traffic_statistics(struct traffic_stats* stats, time_t current, unsigned long period_between_prints);

struct subscriber_stats
{
    /** timestamp for last period **/
    time_t              first_timestamp; /* unix time in seconds */
    time_t              last_timestamp; /* unix time in seconds */
    unsigned long       period_between_prints; /* in seconds */

    /**(1.4.1) current number of subscribers in db*/
    unsigned long       hash_length;

    /** (1.4.2) how many subscribers are added/deleted in db. rate of adding/deleting*/
    unsigned long long  subscriber_added_start;
    unsigned long long  subscriber_added_period;
    unsigned long long  subscriber_deleted_start;
    unsigned long long  subscriber_deleted_period;

    /**(1.4.3) how many times same IP is used to update a different subscriber (implicit logout)*/
    unsigned long long  subscriber_implicit_logout_start;
    unsigned long long  subscriber_implicit_logout_period;

    /**(1.4.4) how many times deletion failed as the IP was not found*/
    unsigned long long  subscriber_deleted_failed_start;
    unsigned long long  subscriber_deleted_failed_period;

    /** update for subscriber but it already exist with no name change */
    unsigned long long  update_no_op_start;
    unsigned long long  update_no_op_period;

    /** failed to lookup subscriber by IP */
    unsigned long long  http_subscriber_not_found_start;
    unsigned long long  http_subscriber_not_found_period;;

    /**(1.4.5) synching with redis: how many subscribers were synched,
    count synch errors of each type: here the counts are: from restart, the last synch (not related to period)*/
    unsigned long       successful_syncs;
};

extern void print_subscriber_statistics(struct subscriber_stats* stats, time_t current, int last);
extern void init_subscriber_statistics(struct subscriber_stats* stats, time_t current, unsigned long period_between_prints);


#define HOST_NAME_MAX_LEN  256

#ifdef COLLECT_CPU_TIMES

void start_measurement(struct rusage* ru);
void stop_measurement(struct rusage* ruPrev, unsigned long long *count);

#endif /* #ifdef COLLECT_CPU_TIMES */


#endif

