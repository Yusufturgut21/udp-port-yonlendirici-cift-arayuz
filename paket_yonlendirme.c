#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define PORT1 8100
#define PORT2 8200

void send_packet(const char *interface, const u_char *packet, int length)
{
    int sockfd;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;

    struct ether_header *eth_header = (struct ether_header *)packet;
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("Socket oluşturma hatası");
        exit(1);
    }

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("IFINDEX atama hatası");
        close(sockfd);
        exit(1);
    }

    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, eth_header->ether_dhost, ETH_ALEN);

    if (ntohs(udph->dest) == PORT1)
    {
        udph->dest = htons(8101);
    }
    else if (ntohs(udph->dest) == PORT2)
    {
        udph->dest = htons(8201);
    }

    if (sendto(sockfd, packet, length, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)
    {
        perror("Paket gönderme hatası");
    }
    else
    {
        printf("Paket %s arayüzünden hedef porta gönderildi: %d\n", interface, ntohs(udph->dest));
    }

    close(sockfd);
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    char *interface = (char *)user;
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    if (iph->protocol == IPPROTO_UDP)
    {
        if (ntohs(udph->dest) == PORT1 || ntohs(udph->dest) == PORT2)
        {
            printf("[%s] UDP paket tespit edildi. Hedef port: %d\n", interface, ntohs(udph->dest));
            send_packet(interface, packet, pkthdr->caplen);
        }
    }
}

void *pcap_thread(void *arg)
{
    char *interface = (char *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Cihaz açılamadı %s: %s\n", interface, errbuf);
        pthread_exit(NULL);
    }

    printf("%s arayüzü üzerinde dinleme başlatıldı.\n", interface);
    pcap_loop(handle, -1, pcap_callback, (u_char *)interface);

    pcap_close(handle);
    pthread_exit(NULL);
}

int main()
{
    char *interface1 = "enp0s3";
    char *interface2 = "enp0s3";

    pthread_t thread1, thread2;

    pthread_create(&thread1, NULL, pcap_thread, (void *)interface1);
    pthread_create(&thread2, NULL, pcap_thread, (void *)interface2);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}