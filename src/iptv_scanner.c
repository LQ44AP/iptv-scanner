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
#include <ctype.h>

// --- 数据结构 ---
typedef struct {
    char ip_port[32];
    char name[64];
} DictEntry;

// --- 全局变量 ---
FILE *fp_all = NULL;     // 全量输出
FILE *fp_hd  = NULL;     // 高清/4K输出
int global_found[256];     
int g_wait_time = 2;       
int g_link_offset = 14;    

DictEntry *g_dict = NULL;
int g_dict_count = 0;

char **g_city_list = NULL;
int g_city_count = 0;

// ================= 辅助函数 =================

void load_dict(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("[警告] 字典文件未找到: %s\n", path); return; }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *name = strtok(line, ",");
        char *url = strtok(NULL, ",");
        if (name && url) {
            g_dict = realloc(g_dict, (g_dict_count + 1) * sizeof(DictEntry));
            strncpy(g_dict[g_dict_count].name, name, 63);
            char *p = strstr(url, "://");
            strncpy(g_dict[g_dict_count].ip_port, p ? p + 3 : url, 31);
            g_dict_count++;
        }
    }
    fclose(f);
    printf("[系统] 已加载字典记录: %d 条\n", g_dict_count);
}

void load_cities(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("[警告] 城市列表未找到。\n"); return; }
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 0) {
            g_city_list = realloc(g_city_list, (g_city_count + 1) * sizeof(char *));
            g_city_list[g_city_count] = strdup(line);
            g_city_count++;
        }
    }
    fclose(f);
    printf("[系统] 已加载城市关键词: %d 个\n", g_city_count);
}

void get_pure_name(const char* source, char* dest) {
    strcpy(dest, source);
    const char* keywords[] = {"超高清", "高清", "标清", "频道", "UHD", "FHD", "4K", "8K", "HD", "hd", "4k"};
    for (int i = 0; i < 11; i++) {
        char* p;
        while ((p = strstr(dest, keywords[i]))) {
            size_t len = strlen(keywords[i]);
            memmove(p, p + len, strlen(p + len) + 1);
        }
    }
    size_t dlen = strlen(dest);
    while (dlen > 0 && (ispunct(dest[dlen-1]) || isspace(dest[dlen-1]))) dest[--dlen] = '\0';
}

const char* get_category(const char* name) {
    if (strstr(name, "CCTV")) return "央视频道";
    if (strstr(name, "卫视")) return "卫视频道";
    for (int i = 0; i < g_city_count; i++) {
        if (strstr(name, g_city_list[i])) return "地方频道";
    }
    if (strstr(name, "影") || strstr(name, "剧") || strstr(name, "院")) return "影视频道";
    if (strstr(name, "体育") || strstr(name, "足球")) return "体育频道";
    if (strstr(name, "少儿") || strstr(name, "动画")) return "少儿频道";
    return "其他频道";
}

const char* get_quality(const char* name) {
    if (strstr(name, "4K") || strstr(name, "超高清")) return "4K";
    if (strstr(name, "HD") || strstr(name, "高清") || strstr(name, "1080")) return "高清";
    return "标清";
}

// ================= 核心逻辑 =================

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    uint16_t dport = ntohs(*(uint16_t *)(udp_ptr + 2));
    const u_char *payload = udp_ptr + 8;
    
    uint32_t dest_ip_val = ntohl(ip_hdr->ip_dst.s_addr);
    int last_byte = dest_ip_val & 0xFF;

    if (last_byte < 0 || last_byte > 255 || global_found[last_byte]) return;

    if (payload[0] == 0x80 || payload[0] == 0x47) {
        global_found[last_byte] = 1; 
        char *ip_str = inet_ntoa(ip_hdr->ip_dst);
        
        char current_key[48], pure_name[64];
        sprintf(current_key, "%s:%d", ip_str, dport);
        const char *raw_name = "未识别频道";
        for(int i=0; i<g_dict_count; i++) {
            if(strcmp(current_key, g_dict[i].ip_port) == 0) { raw_name = g_dict[i].name; break; }
        }

        get_pure_name(raw_name, pure_name);
        const char *cat = get_category(raw_name);
        const char *qua = get_quality(raw_name);
        
        printf("[✔] 发现: %-15s | %-12s | %s-%s\n", ip_str, raw_name, cat, qua);
        
        // 1. 写入全量文件
        if (fp_all) {
            fprintf(fp_all, "#EXTINF:-1 tvg-name=\"%s\" group-title=\"%s-%s\",%s\n", 
                    pure_name, cat, qua, raw_name);
            fprintf(fp_all, "rtp://%s:%d\n", ip_str, dport);
            fflush(fp_all); 
        }

        // 2. 写入高清文件 (过滤掉标清)
        if (fp_hd && (strcmp(qua, "标清") != 0)) {
            fprintf(fp_hd, "#EXTINF:-1 tvg-name=\"%s\" group-title=\"%s\",%s\n", 
                    pure_name, cat, pure_name);
            fprintf(fp_hd, "rtp://%s:%d\n", ip_str, dport);
            fflush(fp_hd);
        }
    }
}

void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte) {
    if (global_found[last_byte]) return;
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
            pcap_dispatch(handle, -1, packet_handler, NULL);
            if (global_found[last_byte]) break;
            usleep(20000); 
        }
        setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    }
    close(s);
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        printf("\nIPTV 终极版扫描器\n用法: %s <网卡> <M3U保存> <字典路径> <城市路径> <等待秒数> <网段1>...\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char *save_path = argv[2];
    load_dict(argv[3]);
    load_cities(argv[4]);
    g_wait_time = atoi(argv[5]);

    // 初始化两个文件
    fp_all = fopen(save_path, "w");
    if (!fp_all) { perror("全量文件创建失败"); return 1; }
    
    char hd_path[256];
    snprintf(hd_path, sizeof(hd_path), "%s", save_path);
    char *dot = strrchr(hd_path, '.');
    if (dot) strcpy(dot, "_hd.m3u"); else strcat(hd_path, "_hd.m3u");
    
    fp_hd = fopen(hd_path, "w");
    if (!fp_hd) { perror("高清文件创建失败"); return 1; }

    fprintf(fp_all, "#EXTM3U\n");
    fprintf(fp_hd, "#EXTM3U\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(dev, errbuf);
    if (!handle) return 1;
    pcap_set_snaplen(handle, 128);
    pcap_set_timeout(handle, 100);
    pcap_activate(handle);

    // 链路偏移自动检测
    int link_type = pcap_datalink(handle);
    if (link_type == DLT_EN10MB) g_link_offset = 14;
    else if (link_type == DLT_LINUX_SLL) g_link_offset = 16;
    else if (link_type == DLT_NULL) g_link_offset = 4;

    printf("[*] 扫描启动 | 全量: %s | 高清: %s\n----------------------------------\n", save_path, hd_path);
    for (int i = 6; i < argc; i++) {
        memset(global_found, 0, sizeof(global_found)); 
        for (int j = 1; j <= 254; j++) scan_single_ip(handle, argv[i], j);
    }

    pcap_close(handle);
    fclose(fp_all);
    if(fp_hd) fclose(fp_hd);
    return 0;
}
