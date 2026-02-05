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
int global_found[256];     
int g_wait_time = 2;       // 每个IP默认等待秒数
int g_channel_count = 1;
int g_link_offset = 14;    

// 自动识别链路层头部长度
void setup_link_offset(pcap_t *handle) {
    int link_type = pcap_datalink(handle);
    switch (link_type) {
        case DLT_EN10MB:      g_link_offset = 14; break;
        case DLT_LINUX_SLL:   g_link_offset = 16; break;
        case DLT_NULL:        g_link_offset = 4;  break;
        default:              g_link_offset = 14;
    }
}

// 抓包回调函数
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    int ip_header_len = ip_hdr->ip_hl * 4;
    
    // 定位 UDP 头部
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    uint16_t dport = ntohs(*(uint16_t *)(udp_ptr + 2));

    // 定位载荷 (UDP头占8字节)
    const u_char *payload = udp_ptr + 8;
    
    uint32_t dest_ip_val = ntohl(ip_hdr->ip_dst.s_addr);
    int last_byte = dest_ip_val & 0xFF;

    if (last_byte < 0 || last_byte > 255 || global_found[last_byte]) return;

    // 指纹识别：RTP (0x80) 或 TS (0x47)
    if (payload[0] == 0x80 || payload[0] == 0x47) {
        global_found[last_byte] = 1; 
        char *ip_str = inet_ntoa(ip_hdr->ip_dst);
        
        printf("\n[✔] 发现频道: %-15s 端口: %-5d (%s)", 
               ip_str, dport, (payload[0] == 0x80) ? "RTP" : "TS");
        
        if (fp_out) {
            fprintf(fp_out, "#EXTINF:-1,IPTV频道-%03d (%s)\n", g_channel_count++, ip_str);
            fprintf(fp_out, "rtp://%s:%d\n", ip_str, dport);
            fflush(fp_out); 
        }
    }
}

// 单线程扫描核心函数
void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte) {
    if (global_found[last_byte]) return;

    char mcast_ip[16];
    sprintf(mcast_ip, "%s.%d", prefix, last_byte);
    
    printf("\r[*] 正在探测: %-15s... ", mcast_ip);
    fflush(stdout);

    // 1. 创建 Socket 并加入组播组 (IGMP Join)
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); 

    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
        // 2. 监听数据包
        time_t start_time = time(NULL);
        while (time(NULL) - start_time < g_wait_time) {
            // 每次抓取少量数据包，-1 表示根据 pcap 缓冲区情况处理
            pcap_dispatch(handle, -1, packet_handler, NULL);
            
            // 如果在等待时间内已经识别到流，直接退出当前 IP 的等待
            if (global_found[last_byte]) break;
            
            usleep(20000); // 20ms 休息，平衡响应速度和 CPU
        }
        // 3. 离开组播组 (IGMP Leave)
        setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    }
    
    close(s);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("\nIPTV 组播单线程扫描器\n");
        printf("用法: %s <网卡> <M3U存放路径> <等待秒数> <网段前缀1> [网段2...]\n", argv[0]);
        printf("示例: %s eth0 ./iptv.m3u 3 239.81.0 239.81.1\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char *save_path = argv[2];
    g_wait_time = atoi(argv[3]);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    fp_out = fopen(save_path, "w");
    if (!fp_out) { perror("无法创建文件"); return 1; }
    fprintf(fp_out, "#EXTM3U\n");

    // 初始化 pcap
    pcap_t *handle = pcap_create(dev, errbuf);
    if (!handle) { fprintf(stderr, "错误: %s\n", errbuf); return 1; }
    
    pcap_set_snaplen(handle, 128); // 只抓头部，提高性能
    pcap_set_timeout(handle, 100); // 设置读超时为 100ms
    if (pcap_activate(handle) != 0) { fprintf(stderr, "激活失败: %s\n", pcap_geterr(handle)); return 1; }

    setup_link_offset(handle);
    printf("[*] 环境就绪: 链路类型 %s, 偏移 %d 字节\n", 
           pcap_datalink_val_to_name(pcap_datalink(handle)), g_link_offset);

    // 循环扫描网段
    for (int arg_idx = 4; arg_idx < argc; arg_idx++) {
        char *prefix = argv[arg_idx];
        memset(global_found, 0, sizeof(global_found)); 
        printf("\n>>> 扫描目标网段: %s.0/24\n", prefix);
        
        for (int i = 1; i <= 254; i++) {
            scan_single_ip(handle, prefix, i);
        }
    }

    printf("\n\n扫描完成！结果已存入: %s\n", save_path);
    pcap_close(handle);
    fclose(fp_out);
    return 0;
}
