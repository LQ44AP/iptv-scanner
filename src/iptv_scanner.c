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

#define RTP_PAYLOAD_START 42 

FILE *fp_out = NULL;
int global_found[256];     // 全局去重：记录当前网段已发现的 IP
int g_batch_size = 5;
int g_wait_time = 5;
int g_channel_count = 1;   // M3U 频道计数器

// 核心指纹识别与 M3U 写入逻辑
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + 14);
    const u_char *payload = packet + RTP_PAYLOAD_START;
    
    uint32_t dest_ip_val = ntohl(ip_hdr->ip_dst.s_addr);
    int last_byte = dest_ip_val & 0xFF;

    // 全局去重逻辑
    if (last_byte < 0 || last_byte > 255 || global_found[last_byte]) return;

    // 指纹识别：RTP (0x80) 或 TS (0x47)
    if (payload[0] == 0x80 || payload[0] == 0x47) {
        global_found[last_byte] = 1; 
        uint16_t dport = ntohs(*(uint16_t *)(packet + 36));
        char *ip_str = inet_ntoa(ip_hdr->ip_dst);
        
        printf("\n[✔] 捕获成功: %-15s 端口: %-5d", ip_str, dport);
        
        if (fp_out) {
            // 写入 M3U 格式：频道信息行 + 播放地址行
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

    printf("\n扫描批次: %s.%-3d - .%-3d ", prefix, start, 
           (start + g_batch_size - 1 > 254) ? 254 : start + g_batch_size - 1);
    fflush(stdout);

    for (int i = 0; i < g_batch_size; i++) {
        int last_byte = start + i;
        if (last_byte > 254) break;
        if (global_found[last_byte]) continue;

        char mcast_ip[16];
        sprintf(mcast_ip, "%s.%d", prefix, last_byte);
        
        socks[active_socks] = socket(AF_INET, SOCK_DGRAM, 0);
        mreqs[active_socks].imr_multiaddr.s_addr = inet_addr(mcast_ip);
        mreqs[active_socks].imr_interface.s_addr = htonl(INADDR_ANY); 
        
        if (setsockopt(socks[active_socks], IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqs[active_socks], sizeof(mreqs[active_socks])) == 0) {
            active_socks++;
        }
    }

    // 核心监听循环
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < g_wait_time) {
        pcap_dispatch(handle, -1, packet_handler, NULL);
        usleep(10000); 
    }

    // 资源释放
    for (int i = 0; i < active_socks; i++) {
        setsockopt(socks[i], IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreqs[i], sizeof(mreqs[i]));
        close(socks[i]);
    }
    sleep(2); // 强制静默期，防止跨批次重复
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("\n==========================================\n");
        printf("   IPTV 组播扫描 \n");
        printf("==========================================\n");
        printf("用法: %s <网卡> <M3U保存路径> <并发数> <等待秒> <IP段1> [IP段2...]\n", argv[0]);
        printf("示例: %s lan1 /www/iptv.m3u 5 5 239.81.0 239.81.1\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char *save_path = argv[2];
    g_batch_size = atoi(argv[3]);
    g_wait_time = atoi(argv[4]);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    fp_out = fopen(save_path, "w");
    if (!fp_out) { perror("无法创建 M3U 文件"); return 1; }
    fprintf(fp_out, "#EXTM3U\n"); // 写入 M3U 标准头

    pcap_t *handle = pcap_create(dev, errbuf);
    pcap_set_snaplen(handle, 100);
    pcap_set_buffer_size(handle, 8*1024*1024); // 8MB 接收缓冲
    pcap_activate(handle);

    for (int arg_idx = 5; arg_idx < argc; arg_idx++) {
        char *prefix = argv[arg_idx];
        memset(global_found, 0, sizeof(global_found)); 

        struct bpf_program bpf_fp;
        char filter_exp[64];
        sprintf(filter_exp, "udp and dst net %s.0/24", prefix);
        pcap_compile(handle, &bpf_fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
        pcap_setfilter(handle, &bpf_fp);

        printf("\n\n>>> 正在扫描网段: %s.0/24", prefix);
        
        // 双轮扫描机制：首轮覆盖 + 补偿覆盖
        printf("\n--- 第一轮扫描 ---");
        for (int i = 1; i <= 254; i += g_batch_size) scan_batch(handle, prefix, i);
        
        printf("\n--- 第二轮补扫 ---");
        for (int i = 1; i <= 254; i += g_batch_size) scan_batch(handle, prefix, i);
        
        pcap_freecode(&bpf_fp);
    }

    printf("\n\n所有扫描已完成，播放列表已生成至: %s\n", save_path);
    pcap_close(handle);
    fclose(fp_out);
    return 0;
}
