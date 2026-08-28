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
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>

// 常量定义
#define MAX_POOL_SIZE 5000
#define HASH_TABLE_SIZE 4096
#define MAX_LINE_LEN 256
#define MAX_NETWORKS 10
#define ETHERTYPE_VLAN 0x8100      // 802.1Q VLAN 标签 EtherType
#define ETHERTYPE_QINQ 0x88A8      // 802.1ad QinQ 标签 EtherType

// 结构体：记录唯一的 IP 和端口组合
typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t proto_type;  // 0=RTP, 1=TS
} DiscoveredNode;

// 哈希表节点
typedef struct HashNode {
    uint64_t key;
    struct HashNode *next;
} HashNode;

// 统计信息
typedef struct {
    int total_packets;
    int rtp_packets;
    int ts_packets;
    int duplicate_packets;
    int unique_channels;
    int hash_collisions;
    int invalid_packets;
} ScanStats;

// 全局变量
static volatile sig_atomic_t stop_flag = 0;
static FILE *fp_out = NULL;
static FILE *log_file = NULL;
static int g_wait_time = 2;
static int g_channel_count = 1;
static int g_link_offset = 14;      // 基础链路层偏移（不含 VLAN）
static int g_link_type = -1;        // 链路层类型，用于 VLAN 检测
static ScanStats g_stats = {0};

// 发现节点池和哈希表
static DiscoveredNode g_pool[MAX_POOL_SIZE];
static int g_pool_count = 0;
static HashNode *hash_table[HASH_TABLE_SIZE] = {0};

// ==================== 工具函数 ====================
char* get_current_time() {
    static char buffer[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

void log_message(const char *format, ...) {
    va_list args, args_copy;
    
    va_start(args, format);
    va_copy(args_copy, args);
    
    printf("[%s] ", get_current_time());
    vprintf(format, args);
    va_end(args);
    
    if (log_file) {
        fprintf(log_file, "[%s] ", get_current_time());
        vfprintf(log_file, args_copy, args_copy);
        fflush(log_file);
    }
    va_end(args_copy);
}

uint64_t make_key(uint32_t ip, uint16_t port) {
    return ((uint64_t)ip << 16) | port;
}

int is_duplicate(uint32_t ip, uint16_t port) {
    uint64_t key = make_key(ip, port);
    unsigned int index = key % HASH_TABLE_SIZE;
    
    HashNode *node = hash_table[index];
    while (node) {
        if (node->key == key) {
            g_stats.duplicate_packets++;
            return 1;
        }
        node = node->next;
    }
    
    HashNode *new_node = (HashNode*)malloc(sizeof(HashNode));
    if (!new_node) {
        log_message("警告: 哈希节点内存分配失败\n");
        return 1; // 内存分配失败时当作重复处理，防止数据结构崩溃
    }
    new_node->key = key;
    new_node->next = hash_table[index];
    
    if (hash_table[index] != NULL) {
        g_stats.hash_collisions++;
    }
    hash_table[index] = new_node;
    
    return 0;
}

void free_hash_table() {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode *node = hash_table[i];
        while (node) {
            HashNode *temp = node;
            node = node->next;
            free(temp);
        }
        hash_table[i] = NULL;
    }
}

// ==================== 协议检测函数 ====================
int is_valid_rtp(const u_char *payload, int payload_len) {
    if (payload_len < 12) return 0;
    if ((payload[0] & 0xC0) != 0x80) return 0; // RFC 3550 Version 必须为 2
    if ((payload[1] & 0x7F) > 127) return 0;
    return 1;
}

int is_valid_ts(const u_char *payload, int payload_len) {
    if (payload_len < 188) return 0;
    int checked_count = 0;
    for (int offset = 0; offset + 188 <= payload_len && checked_count < 3; offset += 188) {
        if (payload[offset] != 0x47) return 0;
        checked_count++;
    }
    return checked_count > 0;
}

// ==================== 信号处理函数 ====================
void signal_handler(int signum) {
    stop_flag = 1;
    log_message("收到信号 %d，正在优雅退出...\n", signum);
}

// ==================== 链路层偏移设置 ====================
void setup_link_offset(pcap_t *handle) {
    g_link_type = pcap_datalink(handle);
    switch (g_link_type) {
        case DLT_EN10MB:      g_link_offset = 14; break;
        case DLT_LINUX_SLL:   g_link_offset = 16; break;
        case DLT_NULL:        g_link_offset = 4;  break;
        case DLT_RAW:         g_link_offset = 0;  break;
        default:              
            log_message("未知链路层类型: %d，使用默认偏移14\n", g_link_type);
            g_link_offset = 14;
    }
    log_message("链路层偏移设置为: %d (基础偏移，VLAN动态处理)\n", g_link_offset);
}

// ==================== 数据包处理函数 ====================
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    g_stats.total_packets++;
    
    // ----- 动态计算实际链路层偏移（支持 Single / Double VLAN） -----
    int offset = g_link_offset;
    if (g_link_type == DLT_EN10MB && header->caplen >= 14) {
        uint16_t eth_type = (packet[12] << 8) | packet[13];
        // 循环跳过 VLAN / QinQ 报头
        while ((eth_type == ETHERTYPE_VLAN || eth_type == ETHERTYPE_QINQ) && 
               (header->caplen >= (bpf_u_int32)(offset + 4))) {
            offset += 4;
            eth_type = (packet[offset - 2] << 8) | packet[offset - 1];
        }
    }
    
    // 1. 安全边界检查：确保包长足够容纳链路层 + IP头
    if (header->caplen < (bpf_u_int32)(offset + sizeof(struct ip))) {
        g_stats.invalid_packets++;
        return;
    }

    struct ip *ip_hdr = (struct ip *)(packet + offset);
    
    if (ip_hdr->ip_v != 4 || ip_hdr->ip_p != IPPROTO_UDP) return;

    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_ptr = packet + offset + ip_header_len;
    
    // 2. 安全边界检查：确保 UDP 头部完全可读
    if (header->caplen < (bpf_u_int32)(offset + ip_header_len + sizeof(struct udphdr))) {
        g_stats.invalid_packets++;
        return;
    }

    struct udphdr *udp_hdr = (struct udphdr *)udp_ptr;
    uint32_t dest_ip = ip_hdr->ip_dst.s_addr;
    uint16_t dport_net = udp_hdr->uh_dport;
    
    // 3. 识别有效载荷
    int payload_len = header->caplen - (offset + ip_header_len + sizeof(struct udphdr));
    if (payload_len <= 0) {
        g_stats.invalid_packets++;
        return;
    }
    
    const u_char *payload = udp_ptr + sizeof(struct udphdr);
    int is_rtp = 0, is_ts = 0;
    
    if (payload_len >= 12 && is_valid_rtp(payload, payload_len)) {
        is_rtp = 1;
    } else if (payload_len >= 188 && is_valid_ts(payload, payload_len)) {
        is_ts = 1;
    }
    
    if (!is_rtp && !is_ts) {
        return;
    }

    // 4. 全局去重校验
    if (is_duplicate(dest_ip, dport_net)) {
        return;
    }

    if (is_rtp) g_stats.rtp_packets++;
    if (is_ts)  g_stats.ts_packets++;

    // 5. 存入全局池
    if (g_pool_count < MAX_POOL_SIZE) {
        g_pool[g_pool_count].ip = dest_ip;
        g_pool[g_pool_count].port = dport_net;
        g_pool[g_pool_count].proto_type = is_rtp ? 0 : 1;
        g_pool_count++;
        g_stats.unique_channels++;
    } else {
        static int warned = 0;
        if (!warned) {
            log_message("警告：节点池已满（%d个），后续节点将被忽略\n", MAX_POOL_SIZE);
            warned = 1;
        }
        return;
    }

    // 6. 输出发现的信息
    char ip_str[INET_ADDRSTRLEN]; 
    if (inet_ntop(AF_INET, &dest_ip, ip_str, sizeof(ip_str)) == NULL) {
        strncpy(ip_str, "无效IP", sizeof(ip_str));
    }
    
    uint16_t dport_host = ntohs(dport_net);
    const char *proto_name = is_rtp ? "RTP" : "TS";
    const char *proto_scheme = is_rtp ? "rtp" : "udp";

    log_message("发现新频道: %-15s 端口: %-5d 类型: %s\n", 
                ip_str, dport_host, proto_name);
    
    if (fp_out) {
        fprintf(fp_out, "#EXTINF:-1,IPTV频道-%03d (%s:%d)\n", 
                g_channel_count++, ip_str, dport_host);
        fprintf(fp_out, "%s://%s:%d\n", proto_scheme, ip_str, dport_host);
        fflush(fp_out);
    }
}

// ==================== 单 IP 扫描函数 ====================
void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte) {
    char mcast_ip[32]; // 扩大缓冲区大小防止溢出
    snprintf(mcast_ip, sizeof(mcast_ip), "%s.%d", prefix, last_byte);
    
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        log_message("创建套接字失败: %s\n", strerror(errno));
        return;
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
    if (mreq.imr_multiaddr.s_addr == INADDR_NONE) {
        log_message("无效的多播地址: %s\n", mcast_ip);
        close(s);
        return;
    }
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
        time_t start_time = time(NULL);
        log_message("开始监听多播组: %s\n", mcast_ip);
        
        while (time(NULL) - start_time < g_wait_time && !stop_flag) {
            pcap_dispatch(handle, 100, packet_handler, NULL);
            usleep(20000);
        }
        
        setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        log_message("结束监听多播组: %s\n", mcast_ip);
    } else {
        log_message("加入多播组失败: %s (%s)\n", mcast_ip, strerror(errno));
    }
    
    close(s);
}

// ==================== 参数验证函数 ====================
int validate_arguments(int argc, char *argv[]) {
    if (argc < 5) {
        printf("\nIPTV 严格去重探测扫描器 - 增强修复版 (支持VLAN/QinQ)\n");
        printf("用法: %s <网卡> <M3U保存路径> <等待秒数> <网段1> [网段2...]\n", argv[0]);
        printf("示例: %s eth0 /tmp/iptv.m3u 2 239.81.0 239.81.1\n\n", argv[0]);
        printf("参数说明:\n");
        printf("  网卡:         网络接口名称 (使用 ifconfig 查看)\n");
        printf("  M3U保存路径: Output M3U 文件路径\n");
        printf("  等待秒数:     每个多播地址监听时间(1-60秒)\n");
        printf("  网段:         多播网段，如239.81.0 (支持1-10个)\n");
        return 0;
    }
    
    g_wait_time = atoi(argv[3]);
    if (g_wait_time <= 0 || g_wait_time > 60) {
        printf("错误：等待时间应在1-60秒之间\n");
        return 0;
    }
    
    int valid_networks = 0;
    for (int i = 4; i < argc && i < 4 + MAX_NETWORKS; i++) {
        int a, b, c;
        if (sscanf(argv[i], "%d.%d.%d", &a, &b, &c) != 3) {
            printf("错误：无效的网段格式: %s\n", argv[i]);
            return 0;
        }
        if (a < 224 || a > 239) {
            printf("警告：%s 可能不是有效的多播地址 (应在224.0.0.0-239.255.255.255范围内)\n", argv[i]);
        }
        valid_networks++;
    }
    
    if (valid_networks == 0) {
        printf("错误：至少需要指定一个网段\n");
        return 0;
    }
    
    return 1;
}

// ==================== 打印统计信息 ====================
void print_statistics() {
    printf("\n============ 扫描统计信息 ============\n");
    printf("总数据包数:         %d\n", g_stats.total_packets);
    printf("RTP包数:            %d\n", g_stats.rtp_packets);
    printf("TS包数:             %d\n", g_stats.ts_packets);
    printf("重复包数:           %d\n", g_stats.duplicate_packets);
    printf("无效包数:           %d\n", g_stats.invalid_packets);
    printf("唯一频道数:         %d\n", g_stats.unique_channels);
    printf("哈希碰撞次数:       %d\n", g_stats.hash_collisions);
    printf("M3U频道数:          %d\n", g_channel_count - 1);
    printf("====================================\n");
}

// ==================== 主函数 ====================
int main(int argc, char *argv[]) {
    time_t start_time = time(NULL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (!validate_arguments(argc, argv)) {
        return 1;
    }
    
    log_file = fopen("/tmp/iptv_scan.log", "a");
    if (!log_file) {
        printf("警告：无法创建日志文件，仅输出到控制台\n");
    } else {
        fprintf(log_file, "\n======= IPTV扫描开始于 %s =======\n", get_current_time());
    }
    
    fp_out = fopen(argv[2], "w");
    if (!fp_out) {
        log_message("无法创建输出文件: %s (%s)\n", argv[2], strerror(errno));
        if (log_file) fclose(log_file);
        return 1;
    }
    fprintf(fp_out, "#EXTM3U\n");
    fprintf(fp_out, "# Generated by IPTV Scanner at %s\n", get_current_time());
    fprintf(fp_out, "# Format: EXTINF line shows IP:Port\n");
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(argv[1], errbuf);
    if (!handle) {
        log_message("网卡错误: %s\n", errbuf);
        if (fp_out) fclose(fp_out);
        if (log_file) fclose(log_file);
        return 1;
    }
    
    pcap_set_snaplen(handle, 256);
    pcap_set_promisc(handle, 0);
    pcap_set_timeout(handle, 100);
    pcap_set_buffer_size(handle, 8 * 1024 * 1024);
    
    if (pcap_activate(handle) != 0) {
        log_message("激活pcap失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        if (fp_out) fclose(fp_out);
        if (log_file) fclose(log_file);
        return 1;
    }
    
    if (pcap_setnonblock(handle, 1, errbuf) < 0) {
        log_message("设置非阻塞模式警告: %s\n", errbuf);
    }
    
    setup_link_offset(handle);
    
    memset(g_pool, 0, sizeof(g_pool));
    memset(&g_stats, 0, sizeof(g_stats));
    
    log_message("开始扫描，使用网卡: %s\n", argv[1]);
    log_message("输出文件: %s\n", argv[2]);
    log_message("每个多播地址等待时间: %d秒\n", g_wait_time);
    log_message("M3U格式: #EXTINF:-1,IPTV频道-序号 (IP:Port)\n");
    
    printf("\n[*] 正在扫描网段，按 Ctrl+C 停止...\n");
    printf("----------------------------------------------------\n");
    
    for (int arg_idx = 4; arg_idx < argc && !stop_flag; arg_idx++) {
        log_message("开始扫描网段: %s\n", argv[arg_idx]);
        
        char prefix[16];
        if (strchr(argv[arg_idx], '.') == NULL) {
            log_message("无效的网段格式: %s\n", argv[arg_idx]);
            continue;
        }
        
        strncpy(prefix, argv[arg_idx], sizeof(prefix) - 1);
        prefix[sizeof(prefix) - 1] = '\0';
        
        for (int i = 1; i <= 254 && !stop_flag; i++) {
            scan_single_ip(handle, prefix, i);
            
            if (i % 10 == 0) {
                printf("进度: %s.%d (%d/254) - 已发现频道: %d\r", 
                       prefix, i, i, g_stats.unique_channels);
                fflush(stdout);
            }
        }
        
        if (stop_flag) {
            log_message("扫描被用户中断\n");
            break;
        }
    }
    
    printf("\n----------------------------------------------------\n");
    
    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, start_time);
    
    if (fp_out) {
        fprintf(fp_out, "# Total channels: %d\n", g_channel_count - 1);
        fprintf(fp_out, "# Scan time: %.1f seconds\n", elapsed);
        fclose(fp_out);
        fp_out = NULL;
    }
    
    print_statistics();
    
    log_message("扫描完成，耗时 %.1f 秒\n", elapsed);
    log_message("发现唯一频道数: %d\n", g_stats.unique_channels);
    
    free_hash_table();
    pcap_close(handle);
    
    if (log_file) {
        fprintf(log_file, "======= IPTV扫描结束于 %s =======\n\n", get_current_time());
        fclose(log_file);
        log_file = NULL;
    }
    
    log_message("结果已保存到 %s\n", argv[2]);
    printf("\n生成的M3U文件格式示例:\n");
    printf("#EXTINF:-1,IPTV频道-001 (239.81.0.1:1234)\n");
    printf("rtp://239.81.0.1:1234\n");
    
    return 0;
}
