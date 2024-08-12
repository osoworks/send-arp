#include <stdio.h>     // 표준 입출력 라이브러리
#include <arpa/inet.h> // 네트워크 관련 라이브러리
#include "send_arp.h"  // ARP 관련 헤더 파일 포함

int main(int argc, char* argv[]) {
    // 프로그램에 전달된 인자의 개수가 올바른지 확인합니다.
    // 첫 번째 인자는 인터페이스 이름, 이후의 인자들은 (sender ip, target ip) 쌍으로 전달됩니다.
    if (argc < 4 || (argc - 2) % 2 != 0) {
        // 인자가 잘못되었을 경우, 사용 방법을 출력합니다.
        printf("Usage: %s <interface> <sender ip1> <target ip1> [<sender ip2> <target ip2> ...]\n", argv[0]);
        return -1; // 프로그램을 종료합니다.
    }

    const char* iface = argv[1]; // 첫 번째 인자는 네트워크 인터페이스 이름입니다.

    // 여러 쌍의 (Sender IP, Target IP)에 대해 반복적으로 ARP 패킷을 생성하고 전송합니다.
    for (int i = 2; i < argc; i += 2) {
        struct ip_addr sender_ip, target_ip;

        // IP 주소를 문자열에서 이진 데이터로 변환합니다.
        if (inet_pton(AF_INET, argv[i], sender_ip.addr) != 1) {
            printf("Invalid sender IP: %s\n", argv[i]);
            continue; // 잘못된 IP 주소가 주어진 경우 해당 쌍을 건너뜁니다.
        }
        if (inet_pton(AF_INET, argv[i + 1], target_ip.addr) != 1) {
            printf("Invalid target IP: %s\n", argv[i + 1]);
            continue; // 잘못된 IP 주소가 주어진 경우 해당 쌍을 건너뜁니다.
        }

        // ARP 패킷 전송
        send_arp(iface, &sender_ip, &target_ip);
    }

    return 0; // 프로그램 종료
}

