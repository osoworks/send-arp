#ifndef SEND_ARP_H
#define SEND_ARP_H

#include <stdint.h>    // 표준 고정 너비 데이터 타입 포함 (u_int8_t 등)
#include <sys/types.h> // 다양한 데이터 타입 정의 포함 (u_int 등)

// 필요한 데이터 타입을 명시적으로 정의
typedef uint8_t u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap.h>      // pcap 라이브러리 포함
#include <netinet/if_ether.h> // 이더넷 헤더 정의 포함

// MAC 주소를 저장할 구조체 정의
struct mac_addr {
    u_char addr[6]; // MAC 주소는 6바이트(48비트)로 이루어져 있습니다.
};

// IP 주소를 저장할 구조체 정의
struct ip_addr {
    u_char addr[4]; // IP 주소는 4바이트(32비트)로 이루어져 있습니다.
};

// ARP 헤더 구조체 정의
struct arp_header {
    u_short htype; // 하드웨어 타입, 이 경우 이더넷을 사용합니다.
    u_short ptype; // 프로토콜 타입, 이 경우 IPv4를 사용합니다.
    u_char hlen;   // 하드웨어 주소 길이 (MAC 주소 길이)
    u_char plen;   // 프로토콜 주소 길이 (IP 주소 길이)
    u_short oper;  // ARP 오퍼레이션, 1은 요청(request), 2는 응답(reply)입니다.
    struct mac_addr sha; // Sender(보내는 사람)의 MAC 주소
    struct ip_addr spa;  // Sender(보내는 사람)의 IP 주소
    struct mac_addr tha; // Target(대상)의 MAC 주소
    struct ip_addr tpa;  // Target(대상)의 IP 주소
};

// 이더넷 헤더 구조체 정의
struct eth_header {
    struct mac_addr dest_mac; // 수신자의 MAC 주소
    struct mac_addr src_mac;  // 발신자의 MAC 주소
    u_short eth_type;         // 이더넷 프레임 타입, ARP 프로토콜을 사용할 때 ETH_P_ARP가 사용됩니다.
};

// 함수 프로토타입 선언
void get_my_mac(const char* iface, struct mac_addr* mac);
void create_arp_packet(u_char* packet, struct mac_addr* attacker_mac, struct ip_addr* sender_ip, struct ip_addr* target_ip);
void send_arp(const char* iface, struct ip_addr* sender_ip, struct ip_addr* target_ip);

#ifdef __cplusplus
}
#endif

#endif // SEND_ARP_H

