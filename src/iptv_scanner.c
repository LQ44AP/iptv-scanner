#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// 全局变量
FILE *fp_out = NULL;
int g_wait_time = 2;       
int g_channel_count = 1;
int g_link_offset = 14;    

// 核心去重结构：用于在扫描当前IP时，记录已经发现并写入文件的端口
uint16_t g_discovered_ports[128]; 
int g_discovered_count = 0;

void setup_link_offset(pcap_t *handle) {
    int link_type = pcap_datalink(handle);
    switch (link_type) {
        case DLT_EN10MB:      g_link_offset = 14; break;
        case DLT_LINUX_SLL:   g_link_offset = 16; break;
        case DLT_NULL:        g_link_offset = 4;  break;
        default:              g_link_offset = 14;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    
    // 1. 提取目标端口
    uint16_t dport = ntohs(*(uint16_t *)(udp_ptr + 2));
    const u_char *payload = udp_ptr + 8;
    
    // 2. 检查该端口在当前 IP 扫描周期内是否已记录过
    for (int i = 0; i < g_discovered_count; i++) {
        if (g_discovered_ports[i] == dport) return; // 已记录，直接丢弃
    }

    // 3. 识别 RTP (0x80) 或 TS (0x47)
    if (payload[0] == 0x80 || payload[0] == 0x47) {
        // 记录到本次 IP 的发现池中
        if (g_discovered_count < 128) {
            g_discovered_ports[g_discovered_count++] = dport;
        }

        char *ip_str = inet_ntoa(ip_hdr->ip_dst);
        
        // 4. 打印并保存
        printf("[✔] 发现频道: %-15s  端口: %-5d  类型: %s\n", 
               ip_str, dport, (payload[0] == 0x80) ? "RTP" : "TS");
        
        if (fp_out) {
            fprintf(fp_out, "#EXTINF:-1,IPTV频道-%03d (%s:%d)\n", g_channel_count++, ip_str, dport);
            fprintf(fp_out, "rtp://%s:%d\n", ip_str, dport);
            fflush(fp_out); 
        }
    }
}

void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte) {
    char mcast_ip[16];
    sprintf(mcast_ip, "%s.%d", prefix, last_byte);
    
    // 每个新 IP 开始扫描前，重置端口记录池
    g_discovered_count = 0;
    memset(g_discovered_ports, 0, sizeof(g_discovered_ports));

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); 

    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
        time_t start_time = time(NULL);
        // 强制等待固定时长，捕获所有可能的端口包
        while (time(NULL) - start_time < g_wait_time) {
            pcap_dispatch(handle, -1, packet_handler, NULL);
            usleep(10000); 
        }
        setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    }
    close(s);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("\nIPTV 全端口单线程去重扫描器\n");
        printf("用法: %s <网卡> <M3U保存路径> <秒数> <前缀1> [前缀2...]\n", argv[0]);
        printf("示例: %s lan1 /www/iptv.m3u 3 239.81.0 239.81.1\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char *save_path = argv[2];
    g_wait_time = atoi(argv[3]);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    fp_out = fopen(save_path, "w");
    if (!fp_out) { perror("文件错误"); return 1; }
    fprintf(fp_out, "#EXTM3U\n");

    pcap_t *handle = pcap_create(dev, errbuf);
    if (!handle) { return 1; }
    pcap_set_snaplen(handle, 128); 
    pcap_set_timeout(handle, 100); 
    if (pcap_activate(handle) != 0) { return 1; }

    setup_link_offset(handle);
    
    printf("[*] 环境就绪: 链路层偏移 %d 字节\n", g_link_offset);
    printf("[*] 正在扫描... 每个IP将持续观察 %d 秒以捕获所有端口\n", g_wait_time);
    printf("----------------------------------------------------\n");

    for (int arg_idx = 4; arg_idx < argc; arg_idx++) {
        char *prefix = argv[arg_idx];
        for (int i = 1; i <= 254; i++) {
            scan_single_ip(handle, prefix, i);
        }
    }

    printf("----------------------------------------------------\n");
    printf("[*] 扫描完成。结果: %s\n", save_path);

    pcap_close(handle);
    fclose(fp_out);
    return 0;
}
