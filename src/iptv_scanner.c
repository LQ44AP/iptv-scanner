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
int g_batch_size = 5;
int g_wait_time = 5;
int g_channel_count = 1;
int g_link_offset = 14;    // 动态链路层偏移量

// 自动识别链路层头部长度
void setup_link_offset(pcap_t *handle) {
    int link_type = pcap_datalink(handle);
    switch (link_type) {
        case DLT_EN10MB:      // 标准以太网
            g_link_offset = 14; 
            break;
        case DLT_LINUX_SLL:   // Linux Cooked (pppoe, any等)
            g_link_offset = 16;
            break;
        case DLT_NULL:        // 回环接口
            g_link_offset = 4;
            break;
        default:
            g_link_offset = 14;
            printf("\n[!] 未知链路类型 %d, 使用默认以太网偏移", link_type);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 1. 定位 IP 头部
    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    
    // 2. 动态计算 IP 头部长度 (处理带有 Options 的特殊情况)
    int ip_header_len = ip_hdr->ip_hl * 4;
    
    // 3. 定位 UDP 头部并提取目标端口 (UDP 目标端口在头部的第 2-4 字节)
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    uint16_t dport = ntohs(*(uint16_t *)(udp_ptr + 2));

    // 4. 定位载荷起始位置 (IP头 + UDP头8字节)
    const u_char *payload = udp_ptr + 8;
    
    uint32_t dest_ip_val = ntohl(ip_hdr->ip_dst.s_addr);
    int last_byte = dest_ip_val & 0xFF;

    // 去重逻辑
    if (last_byte < 0 || last_byte > 255 || global_found[last_byte]) return;

    // 指纹识别：RTP (0x80) 或 TS (0x47)
    if (payload[0] == 0x80 || payload[0] == 0x47) {
        global_found[last_byte] = 1; 
        char *ip_str = inet_ntoa(ip_hdr->ip_dst);
        
        printf("\n[✔] 捕获成功: %-15s 端口: %-5d", ip_str, dport);
        
        if (fp_out) {
            fprintf(fp_out, "#EXTINF:-1,IPTV频道-%03d (%s)\n", g_channel_count++, ip_str);
            fprintf(fp_out, "rtp://%s:%d\n", ip_str, dport);
            fflush(fp_out); 
        }
    }
}

void scan_batch(pcap_t *handle, const char *prefix, int start) {
    int socks[g_batch_size];
    struct ip_mreq mreqs[g_batch_size];
    int active_socks = 0;

    printf("\r扫描中: %s.%-3d - .%-3d ", prefix, start, 
           (start + g_batch_size - 1 > 254) ? 254 : start + g_batch_size - 1);
    fflush(stdout);

    for (int i = 0; i < g_batch_size; i++) {
        int last_byte = start + i;
        if (last_byte > 254) break;
        if (global_found[last_byte]) continue;

        char mcast_ip[16];
        sprintf(mcast_ip, "%s.%d", prefix, last_byte);
        
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        
        mreqs[active_socks].imr_multiaddr.s_addr = inet_addr(mcast_ip);
        mreqs[active_socks].imr_interface.s_addr = htonl(INADDR_ANY); 
        
        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqs[active_socks], sizeof(mreqs[active_socks])) == 0) {
            socks[active_socks] = s;
            active_socks++;
        } else {
            close(s);
        }
    }

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < g_wait_time) {
        pcap_dispatch(handle, -1, packet_handler, NULL);
        usleep(10000); 
    }

    for (int i = 0; i < active_socks; i++) {
        setsockopt(socks[i], IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreqs[i], sizeof(mreqs[i]));
        close(socks[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("用法: %s <网卡> <M3U路径> <并发> <秒> <网段1> [网段2...]\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char *save_path = argv[2];
    g_batch_size = atoi(argv[3]);
    g_wait_time = atoi(argv[4]);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    fp_out = fopen(save_path, "w");
    if (!fp_out) { perror("文件创建失败"); return 1; }
    fprintf(fp_out, "#EXTM3U\n");

    pcap_t *handle = pcap_create(dev, errbuf);
    if (!handle) { fprintf(stderr, "无法创建pcap句柄: %s\n", errbuf); return 1; }
    
    pcap_set_snaplen(handle, 128); // 增加截断长度以容纳 SLL 头部
    pcap_set_buffer_size(handle, 4*1024*1024);
    pcap_set_promisc(handle, 1);
    if (pcap_activate(handle) != 0) { fprintf(stderr, "无法激活网卡: %s\n", pcap_geterr(handle)); return 1; }

    setup_link_offset(handle);
    printf("[*] 链路层: %s, 偏移: %d 字节\n", pcap_datalink_val_to_name(pcap_datalink(handle)), g_link_offset);

    for (int arg_idx = 5; arg_idx < argc; arg_idx++) {
        char *prefix = argv[arg_idx];
        memset(global_found, 0, sizeof(global_found)); 
        printf("\n>>> 扫描网段: %s.0/24\n", prefix);
        
        for (int i = 1; i <= 254; i += g_batch_size) {
            scan_batch(handle, prefix, i);
        }
    }

    printf("\n\n完成！列表已生成: %s\n", save_path);
    pcap_close(handle);
    fclose(fp_out);
    return 0;
}
