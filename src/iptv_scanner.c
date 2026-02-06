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

typedef struct {
    uint32_t ip;
    uint16_t port;
} DiscoveredNode;

typedef struct {
    char ip_str[16];
    int port;
    char name[64];
} DictEntry;

typedef struct {
    char ch_name[64];
    char tvg_name[64];
} TvgEntry;

FILE *fp_out = NULL;
int g_wait_time = 2;       
int g_channel_count = 1;
int g_link_offset = 14;    
char g_logo_prefix[256] = ""; 
char g_epg_url[512] = ""; 

DiscoveredNode g_pool[2000];
int g_pool_count = 0;
DictEntry g_dict[5000]; 
int g_dict_count = 0;
TvgEntry g_tvg[5000];
int g_tvg_count = 0;

// 字符串工具
char* trim_space(char *str) {
    if (!str) return NULL;
    while(isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

// 深度清洗
char* clean_ip_part(char *str) {
    str = trim_space(str);
    char *p_udp = strstr(str, "/udp/");
    char *p_rtp = strstr(str, "/rtp/");
    if (p_udp) str = p_udp + 5; 
    else if (p_rtp) str = p_rtp + 5; 
    else {
        char *p_proto = strstr(str, "://");
        if (p_proto) str = p_proto + 3;
    }
    return trim_space(str);
}

// 智能分类逻辑 (新增体育、少儿)
void get_smart_group(const char *name, const char *tvg_found, char *output_group) {
    char base[32];
    if (strstr(name, "CCTV") || strstr(name, "中央")) strcpy(base, "央视频道");
    else if (strstr(name, "卫视")) strcpy(base, "卫视频道");
    else if (strstr(name, "体育") || strstr(name, "五星") || strstr(name, "劲爆") || strstr(name, "球")) strcpy(base, "体育频道");
    else if (strstr(name, "少儿") || strstr(name, "卡通") || strstr(name, "动漫") || strstr(name, "动画")) strcpy(base, "少儿频道");
    else if (tvg_found != NULL) strcpy(base, "地方频道");
    else strcpy(base, "其他频道");

    if (strstr(name, "高清") || strstr(name, "HD") || strstr(name, "4K")) {
        sprintf(output_group, "%s-高清", base);
    } else if (strstr(name, "标清") || strstr(name, "SD")) {
        sprintf(output_group, "%s-标清", base);
    } else {
        strcpy(output_group, base);
    }
}

void load_tvg(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp) && g_tvg_count < 5000) {
        char *comma = strchr(line, ',');
        if (!comma) continue;
        *comma = '\0';
        strncpy(g_tvg[g_tvg_count].ch_name, trim_space(line), 63);
        strncpy(g_tvg[g_tvg_count].tvg_name, trim_space(comma + 1), 63);
        g_tvg_count++;
    }
    fclose(fp);
}

void load_dict(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp) && g_dict_count < 5000) {
        char *comma = strchr(line, ',');
        if (!comma) continue;
        *comma = '\0';
        char *name_part = trim_space(line);
        char *addr_part = clean_ip_part(comma + 1);
        char *colon = strchr(addr_part, ':');
        if (!colon) continue;
        *colon = '\0';
        strncpy(g_dict[g_dict_count].ip_str, trim_space(addr_part), 15);
        g_dict[g_dict_count].port = atoi(colon + 1);
        strncpy(g_dict[g_dict_count].name, name_part, 63);
        g_dict_count++;
    }
    fclose(fp);
}

const char* find_tvg_name(const char *ch_name) {
    for (int i = 0; i < g_tvg_count; i++) {
        if (strcmp(g_tvg[i].ch_name, ch_name) == 0) return g_tvg[i].tvg_name;
    }
    return NULL;
}

const char* find_channel_name(const char *ip, int port) {
    for (int i = 0; i < g_dict_count; i++) {
        if (g_dict[i].port == port && strcmp(g_dict[i].ip_str, ip) == 0) return g_dict[i].name;
    }
    return NULL;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + g_link_offset);
    if (header->caplen < g_link_offset + 20 || ip_hdr->ip_p != IPPROTO_UDP) return;
    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *udp_ptr = packet + g_link_offset + ip_header_len;
    uint32_t dest_ip = ip_hdr->ip_dst.s_addr;
    uint16_t dport_net = *(uint16_t *)(udp_ptr + 2);

    for (int i = 0; i < g_pool_count; i++) {
        if (g_pool[i].ip == dest_ip && g_pool[i].port == dport_net) return;
    }

    const u_char *payload = udp_ptr + 8;
    if (payload[0] == 0x80 || payload[0] == 0x47) {
        if (g_pool_count < 2000) {
            g_pool[g_pool_count].ip = dest_ip;
            g_pool[g_pool_count].port = dport_net;
            g_pool_count++;
        }

        char ip_str[16], group[64];
        inet_ntop(AF_INET, &dest_ip, ip_str, sizeof(ip_str));
        int port_host = ntohs(dport_net);
        const char *ch_name = find_channel_name(ip_str, port_host);

        if (fp_out) {
            if (ch_name) {
                const char *tvg = find_tvg_name(ch_name);
                get_smart_group(ch_name, tvg, group);
                
                char logo_param[512] = "";
                if (strlen(g_logo_prefix) > 0) {
                    snprintf(logo_param, sizeof(logo_param), " tvg-logo=\"%s%s.png\"", g_logo_prefix, tvg ? tvg : ch_name);
                }

                fprintf(fp_out, "#EXTINF:-1 tvg-name=\"%s\"%s group-title=\"%s\",%s\n", 
                        tvg ? tvg : ch_name, logo_param, group, ch_name);
                printf("[✔] 发现: %-15s | 分组: %-12s | 名称: %s\n", ip_str, group, ch_name);
            } else {
                fprintf(fp_out, "#EXTINF:-1 group-title=\"其他频道\",未知频道-%03d\n", g_channel_count++);
            }
            fprintf(fp_out, "rtp://%s:%d\n", ip_str, port_host);
            fflush(fp_out); 
        }
    }
}

void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte) {
    char mcast_ip[16];
    sprintf(mcast_ip, "%s.%d", prefix, last_byte);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); 
    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
        time_t start = time(NULL);
        while (time(NULL) - start < g_wait_time) pcap_dispatch(handle, -1, packet_handler, NULL);
    }
    close(s);
}

int main(int argc, char *argv[]) {
    if (argc < 9) {
        printf("\nIPTV 全自动分类扫描器 (支持体育/少儿)\n");
        printf("用法: %s <网卡> <M3U保存路径> <城市名列表> <频道名称匹配字典> <超时秒> <Logo链接> <EPG链接> <网段1> ...\n", argv[0]);
        return 1;
    }
    load_dict(argv[3]); load_tvg(argv[4]);
    g_wait_time = atoi(argv[5]);
    if (strcmp(argv[6], "none") != 0) strncpy(g_logo_prefix, argv[6], 255);
    if (strcmp(argv[7], "none") != 0) strncpy(g_epg_url, argv[7], 511);

    fp_out = fopen(argv[2], "w");
    if (strlen(g_epg_url) > 0) fprintf(fp_out, "#EXTM3U x-tvg-url=\"%s\"\n", g_epg_url);
    else fprintf(fp_out, "#EXTM3U\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(argv[1], errbuf);
    pcap_set_snaplen(handle, 128);
    pcap_activate(handle);
    
    int link_type = pcap_datalink(handle);
    g_link_offset = (link_type == DLT_LINUX_SLL) ? 16 : 14;

    for (int i = 8; i < argc; i++) {
        for (int j = 1; j <= 254; j++) scan_single_ip(handle, argv[i], j);
    }
    fclose(fp_out); pcap_close(handle);
    return 0;
}
