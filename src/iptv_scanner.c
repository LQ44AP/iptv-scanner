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

typedef struct {
    uint32_t ip;
    uint16_t port;
} DiscoveredNode;

FILE *fp_out = NULL;
int g_wait_time = 2;       
int g_channel_count = 1;
int g_link_offset = 14;    

DiscoveredNode g_pool[2000]; 
int g_pool_count = 0;

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
    // 基础边界检查
    if (header->caplen < g_link_offset + sizeof(struct ip)) return;

    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    
    // 注意：虽然 BPF 过滤了 UDP，但出于严谨性，保留结构解析逻辑
    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    
    if (header->caplen < (g_link_offset + ip_header_len + 4)) return;

    uint32_t dest_ip = ip_hdr->ip_dst.s_addr;
    uint16_t dport_net = *(uint16_t *)(udp_ptr + 2); 
    
    for (int i = 0; i < g_pool_count; i++) {
        if (g_pool[i].ip == dest_ip && g_pool[i].port == dport_net) return;
    }

    if (header->caplen < (g_link_offset + ip_header_len + 8 + 1)) return;
    const u_char *payload = udp_ptr + 8;

    // 识别有效载荷 (RTP: 0x80, TS: 0x47)
    if (payload[0] == 0x80 || payload[0] == 0x47) {
        if (g_pool_count < 2000) {
            g_pool[g_pool_count].ip = dest_ip;
            g_pool[g_pool_count].port = dport_net;
            g_pool_count++;
        }

        char ip_str[INET_ADDRSTRLEN]; 
        if (inet_ntop(AF_INET, &dest_ip, ip_str, sizeof(ip_str)) == NULL) return;
        
        uint16_t dport_host = ntohs(dport_net);
        const char *proto_type = (payload[0] == 0x80) ? "RTP" : "TS";

        printf("[✔] 发现新频道: %-15s  端口: %-5d  类型: %s\n", 
               ip_str, dport_host, proto_type);
        
        if (fp_out) {
            fprintf(fp_out, "#EXTINF:-1,IPTV频道-%03d (%s)\n", g_channel_count++, proto_type);
            fprintf(fp_out, "rtp://%s:%d\n", ip_str, dport_host);
            fflush(fp_out); 
        }
    }
}

void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte) {
    char mcast_ip[16];
    sprintf(mcast_ip, "%s.%d", prefix, last_byte);
    
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); 

    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
        time_t start_time = time(NULL);
        while (time(NULL) - start_time < g_wait_time) {
            // 每次最多处理 10 个包就返回，避免在单个 IP 阻塞太久
            pcap_dispatch(handle, 10, packet_handler, NULL);
            usleep(20000); 
        }
        setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    }
    close(s);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("\nIPTV 严格去重探测扫描器\n");
        printf("用法: %s <网卡> <M3U保存路径> <等待秒数> <网段1> [网段2...]\n", argv[0]);
        printf("示例: %s lan1 /www/iptv.m3u 2 239.81.0 239.81.1\n", argv[0]);
        return 1;
    }

    g_wait_time = atoi(argv[3]);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    fp_out = fopen(argv[2], "w");
    if (!fp_out) { perror("无法创建输出文件"); return 1; }
    fprintf(fp_out, "#EXTM3U\n");

    pcap_t *handle = pcap_create(argv[1], errbuf);
    if (!handle) { fprintf(stderr, "网卡错误: %s\n", errbuf); return 1; }
    
    pcap_set_snaplen(handle, 128); 
    pcap_set_timeout(handle, 10);  
    if (pcap_activate(handle) != 0) { fprintf(stderr, "激活失败\n"); return 1; }

    setup_link_offset(handle);

    // --- BPF 过滤器设置 ---
    struct bpf_program fcode;
    // 只允许 UDP 且长度大于 100 字节的包进入用户态 (过滤掉常见的嗅探和控制包)
    char filter_exp[] = "udp and greater 100"; 
    
    if (pcap_compile(handle, &fcode, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[!] BPF 编译失败: %s\n", pcap_geterr(handle));
    } else {
        if (pcap_setfilter(handle, &fcode) == -1) {
            fprintf(stderr, "[!] BPF 设置失败: %s\n", pcap_geterr(handle));
        } else {
            printf("[+] BPF 内核过滤器已启用: %s\n", filter_exp);
        }
        pcap_freecode(&fcode); // 编译后的规则已装载进内核，释放内存
    }
    // -----------------------

    memset(g_pool, 0, sizeof(g_pool));
    printf("[*] 开始扫描，按 Ctrl+C 停止...\n\n");

    for (int arg_idx = 4; arg_idx < argc; arg_idx++) {
        for (int i = 1; i <= 254; i++) {
            scan_single_ip(handle, argv[arg_idx], i);
        }
    }

    printf("\n----------------------------------------------------\n");
    printf("[*] 扫描完成。唯一频道总数: %d\n", g_pool_count);
    fclose(fp_out);
    pcap_close(handle);
    return 0;
}
