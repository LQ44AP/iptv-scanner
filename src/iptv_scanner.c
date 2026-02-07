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
#include <pthread.h>

// 全局配置
FILE *fp_out = NULL;
int global_found[256];      
int g_wait_time = 2;        
int g_channel_count = 1;
int g_link_offset = 14;     
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

// 记录当前段捕获到的总数
int current_segment_total = 0;

void setup_link_offset(pcap_t *handle) {
    int link_type = pcap_datalink(handle);
    switch (link_type) {
        case DLT_EN10MB:      g_link_offset = 14; break;
        case DLT_LINUX_SLL:   g_link_offset = 16; break;
        default:              g_link_offset = 14;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->caplen < g_link_offset + 28) return;

    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    uint16_t dport = ntohs(*(uint16_t *)(udp_ptr + 2));
    const u_char *payload = udp_ptr + 8;

    uint32_t dest_ip_val = ntohl(ip_hdr->ip_dst.s_addr);
    int last_byte = dest_ip_val & 0xFF;

    if (payload[0] == 0x80 || payload[0] == 0x47) {
        pthread_mutex_lock(&g_mutex);
        if (global_found[last_byte] == 0) {
            global_found[last_byte] = 1;
            current_segment_total++; // 增加当前段计数
            char ip_str[16];
            strcpy(ip_str, inet_ntoa(ip_hdr->ip_dst));
            
            printf("\r[✔] 发现: %-15s 端口: %-5d\n", ip_str, dport);

            if (fp_out) {
                fprintf(fp_out, "#EXTINF:-1,IPTV-%03d (%s)\n", g_channel_count++, ip_str);
                fprintf(fp_out, "rtp://%s:%d\n", ip_str, dport);
                fflush(fp_out);
            }
        }
        pthread_mutex_unlock(&g_mutex);
    }
}

void* sniffer_worker(void* arg) {
    pcap_t* handle = (pcap_t*)arg;
    pcap_loop(handle, 0, packet_handler, NULL);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("用法: %s <网卡> <M3U路径> <秒数>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    g_wait_time = atoi(argv[3]);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    fp_out = fopen(argv[2], "w");
    if (!fp_out) { perror("文件错误"); return 1; }
    fprintf(fp_out, "#EXTM3U\n");

    pcap_t *handle = pcap_create(dev, errbuf);
    pcap_set_snaplen(handle, 128);
    pcap_set_buffer_size(handle, 2 * 1024 * 1024); // OpenWrt 建议设为 2MB
    pcap_activate(handle);
    setup_link_offset(handle);

    pthread_t sniffer_tid;
    pthread_create(&sniffer_tid, NULL, sniffer_worker, handle);
    pthread_detach(sniffer_tid);

    printf("[*] 智能异步扫描启动。策略：段前20个IP无信号则跳过。\n");

    char prefix[20];
    for (int b = 239; b <= 239; b++) { // 通常只扫 239 段
        for (int c = 0; c <= 255; c++) {
            for (int d = 0; d <= 255; d++) {
                sprintf(prefix, "%d.%d.%d", b, c, d);
                
                pthread_mutex_lock(&g_mutex);
                memset(global_found, 0, sizeof(global_found));
                current_segment_total = 0;
                pthread_mutex_unlock(&g_mutex);

                printf("[扫描] %s.0/24...\r", prefix);
                fflush(stdout);

                int sockets[256] = {0};

                // 第一阶段：探测期（只发前 20 个）
                for (int i = 1; i <= 20; i++) {
                    char mcast_ip[20];
                    sprintf(mcast_ip, "%s.%d", prefix, i);
                    int s = socket(AF_INET, SOCK_DGRAM, 0);
                    struct ip_mreq mreq;
                    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
                    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
                    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
                        sockets[i] = s;
                    }
                }

                // 给交换机 1.5 秒反应时间
                sleep(1.5); 

                // 智能跳过判定
                pthread_mutex_lock(&g_mutex);
                if (current_segment_total == 0) {
                    pthread_mutex_unlock(&g_mutex);
                    // 清理并跳过
                    for (int i = 1; i <= 20; i++) if (sockets[i] > 0) close(sockets[i]);
                    continue; 
                }
                pthread_mutex_unlock(&g_mutex);

                // 第二阶段：补全期（如果发现信号，扫完剩下的）
                for (int i = 21; i <= 254; i++) {
                    char mcast_ip[20];
                    sprintf(mcast_ip, "%s.%d", prefix, i);
                    int s = socket(AF_INET, SOCK_DGRAM, 0);
                    struct ip_mreq mreq;
                    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
                    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
                    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
                        sockets[i] = s;
                    }
                    if (i % 30 == 0) usleep(20000); // 稍微缓冲
                }

                sleep(g_wait_time);

                // 段扫描结束，清理所有 socket
                for (int i = 1; i <= 254; i++) {
                    if (sockets[i] > 0) close(sockets[i]);
                }
            }
        }
    }

    printf("\n[*] 扫描完成。\n");
    pcap_breakloop(handle);
    fclose(fp_out);
    return 0;
}
