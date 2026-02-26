#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// 最大支持频道数
#define MAX_CHANNELS 2048
#define NAME_LEN 128
#define IP_PORT_LEN 32

typedef struct {
    char ip[16];
    int port;
    char name[NAME_LEN];
    char pure_name[NAME_LEN];
    char category[32];
    char quality[8];
} channel_t;

typedef struct {
    char ip_port[IP_PORT_LEN];
    char name[NAME_LEN];
} dict_entry_t;

// 全局变量
int global_found[256];
int g_wait_time = 2;
int g_link_offset = 14;
channel_t channels[MAX_CHANNELS];
int channel_count = 0;
dict_entry_t dict[1024];
int dict_size = 0;
char cities[256][32];
int city_count = 0;

// 可配置变量
const char *epg_url = "";
const char *logo_base = "";
const char *play_prefix = "rtp";   // 默认前缀
const char *dict_path = NULL;      // 字典文件路径（最终使用）
const char *city_path = NULL;      // 城市列表文件路径（最终使用）

// 分类规则
typedef struct {
    const char *keywords;
    const char *cat_name;
} cat_rule_t;

cat_rule_t cat_rules[] = {
    {"CCTV", "央视频道"},
    {"卫视", "卫视频道"},
    {"电影,影视,影院,剧场", "影视频道"},
    {"少儿,动画,卡通,动漫", "少儿频道"},
    {"体育,竞技,足球", "体育频道"},
    {NULL, "其他频道"}
};

// 函数声明
void setup_link_offset(pcap_t *handle);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void scan_single_ip(pcap_t *handle, const char *prefix, int last_byte);
int load_dict(const char *path);
int load_cities(const char *path);
void classify_channel(channel_t *ch);
void clean_name(const char *src, char *dst);
void determine_quality(const char *name, char *quality);
void write_outputs(const char *base_m3u_path);
const char* lookup_dict(const char *ip_port);
void str_toupper(char *s);
int contains_keyword(const char *name, const char *keyword);
void make_group_title(const channel_t *ch, char *group);
void build_url(char *buf, size_t size, const char *prefix, const char *ip, int port);  // 新增辅助函数

// ---------- 函数实现 ----------

int load_dict(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[警告] 字典文件不存在: %s\n", path);
        return 0;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // 去除首尾空白
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';
        if (strlen(p) == 0) continue;

        char name[NAME_LEN], ip_port[IP_PORT_LEN];
        char *comma = strchr(p, ',');
        if (!comma) continue;
        *comma = '\0';
        strncpy(name, p, NAME_LEN-1);
        name[NAME_LEN-1] = '\0';
        strncpy(ip_port, comma+1, IP_PORT_LEN-1);
        ip_port[IP_PORT_LEN-1] = '\0';

        // 去除两端空白
        char *np = name;
        while (*np == ' ' || *np == '\t') np++;
        char *nend = np + strlen(np) - 1;
        while (nend > np && (*nend == ' ' || *nend == '\t')) *nend-- = '\0';
        if (strlen(np) == 0) continue;

        char *ipp = ip_port;
        while (*ipp == ' ' || *ipp == '\t') ipp++;
        char *ipend = ipp + strlen(ipp) - 1;
        while (ipend > ipp && (*ipend == ' ' || *ipend == '\t')) *ipend-- = '\0';
        if (strlen(ipp) == 0) continue;

        strncpy(dict[dict_size].ip_port, ipp, IP_PORT_LEN-1);
        dict[dict_size].ip_port[IP_PORT_LEN-1] = '\0';
        strncpy(dict[dict_size].name, np, NAME_LEN-1);
        dict[dict_size].name[NAME_LEN-1] = '\0';
        dict_size++;
        if (dict_size >= 1024) break;
    }
    fclose(f);
    printf("[系统] 已加载字典记录: %d 条\n", dict_size);
    return dict_size;
}

int load_cities(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[警告] 城市列表文件不存在: %s\n", path);
        return 0;
    }
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';
        if (strlen(p) == 0) continue;
        strncpy(cities[city_count], p, 31);
        cities[city_count][31] = '\0';
        city_count++;
        if (city_count >= 256) break;
    }
    fclose(f);
    printf("[系统] 已加载城市关键词: %d 个\n", city_count);
    return city_count;
}

const char* lookup_dict(const char *ip_port) {
    for (int i = 0; i < dict_size; i++) {
        if (strcmp(dict[i].ip_port, ip_port) == 0)
            return dict[i].name;
    }
    return NULL;
}

void str_toupper(char *s) {
    for (; *s; s++) *s = toupper((unsigned char)*s);
}

int contains_keyword(const char *name, const char *keyword) {
    char upper[NAME_LEN];
    strncpy(upper, name, NAME_LEN-1);
    upper[NAME_LEN-1] = '\0';
    str_toupper(upper);
    return strstr(upper, keyword) != NULL;
}

void classify_channel(channel_t *ch) {
    if (contains_keyword(ch->name, "CCTV")) {
        strcpy(ch->category, "央视频道");
        return;
    }
    if (contains_keyword(ch->name, "卫视")) {
        strcpy(ch->category, "卫视频道");
        return;
    }
    for (int i = 0; i < city_count; i++) {
        if (strstr(ch->name, cities[i]) != NULL) {
            strcpy(ch->category, "地方频道");
            return;
        }
    }
    for (int i = 0; cat_rules[i].keywords != NULL; i++) {
        char keywords[128];
        strncpy(keywords, cat_rules[i].keywords, sizeof(keywords)-1);
        keywords[sizeof(keywords)-1] = '\0';
        char *token = strtok(keywords, ",");
        while (token) {
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && (*end == ' ')) *end-- = '\0';
            if (contains_keyword(ch->name, token)) {
                strcpy(ch->category, cat_rules[i].cat_name);
                return;
            }
            token = strtok(NULL, ",");
        }
    }
    strcpy(ch->category, "其他频道");
}

void clean_name(const char *src, char *dst) {
    char temp[NAME_LEN];
    strncpy(temp, src, NAME_LEN-1);
    temp[NAME_LEN-1] = '\0';

    // 保护特殊词（简化版）
    char *p;
    if ((p = strstr(temp, "CCTV4K")) != NULL) memcpy(p, "PROTECTAA", 9);
    if ((p = strstr(temp, "CCTV5+")) != NULL) memcpy(p, "PROTECTBB", 9);
    if ((p = strstr(temp, "爱上4K")) != NULL) memcpy(p, "PROLOVECC", 9);
    if ((p = strstr(temp, "茶频道")) != NULL) memcpy(p, "PROTEA", 6);

    const char *remove_words[] = {"奥林匹克", "超高清", "高清", "标清", "频道", "字幕", "UHD", "FHD", "4K", "8K", "HD", NULL};
    for (int i = 0; remove_words[i]; i++) {
        char *pos;
        while ((pos = strstr(temp, remove_words[i])) != NULL) {
            size_t len = strlen(remove_words[i]);
            memmove(pos, pos + len, strlen(pos + len) + 1);
        }
    }

    char result[NAME_LEN];
    int j = 0;
    for (int i = 0; temp[i]; i++) {
        unsigned char c = temp[i];
        if (c >= 0x80) { // 中文字符
            result[j++] = c;
        } else if (isalnum(c)) {
            result[j++] = c;
        }
    }
    result[j] = '\0';

    // 恢复保护词
    if ((p = strstr(result, "PROTECTAA")) != NULL) memcpy(p, "CCTV4K", 6);
    if ((p = strstr(result, "PROTECTBB")) != NULL) memcpy(p, "CCTV5+", 6);
    if ((p = strstr(result, "PROLOVECC")) != NULL) memcpy(p, "爱上4K", 6);
    if ((p = strstr(result, "PROTEA")) != NULL) memcpy(p, "茶频道", 6);

    strncpy(dst, result, NAME_LEN-1);
    dst[NAME_LEN-1] = '\0';
}

void determine_quality(const char *name, char *quality) {
    char upper[NAME_LEN];
    strncpy(upper, name, NAME_LEN-1);
    upper[NAME_LEN-1] = '\0';
    str_toupper(upper);

    if (strstr(upper, "4K") || strstr(upper, "超高清"))
        strcpy(quality, "4K");
    else if (strstr(upper, "高清") || strstr(upper, "HD") || strstr(upper, "1080") || strstr(upper, "720"))
        strcpy(quality, "高清");
    else
        strcpy(quality, "标清");
}

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
    uint16_t dport = ntohs(*(uint16_t *)(udp_ptr + 2));
    const u_char *payload = udp_ptr + 8;
    
    uint32_t dest_ip_val = ntohl(ip_hdr->ip_dst.s_addr);
    int last_byte = dest_ip_val & 0xFF;

    if (last_byte < 0 || last_byte > 255 || global_found[last_byte]) return;

    if (payload[0] == 0x80 || payload[0] == 0x47) {
        global_found[last_byte] = 1;
        char *ip_str = inet_ntoa(ip_hdr->ip_dst);
        
        char key[IP_PORT_LEN];
        snprintf(key, sizeof(key), "%s:%d", ip_str, dport);

        const char *chan_name = lookup_dict(key);
        char default_name[NAME_LEN];
        if (!chan_name) {
            snprintf(default_name, sizeof(default_name), "未识别-%s", ip_str);
            chan_name = default_name;
        }

        if (channel_count < MAX_CHANNELS) {
            channel_t *ch = &channels[channel_count++];
            strncpy(ch->ip, ip_str, 15);
            ch->ip[15] = '\0';
            ch->port = dport;
            strncpy(ch->name, chan_name, NAME_LEN-1);
            ch->name[NAME_LEN-1] = '\0';

            clean_name(ch->name, ch->pure_name);
            determine_quality(ch->name, ch->quality);
            classify_channel(ch);

            printf("[✔] 发现频道: %-15s  端口: %-5d  名称: %s [%s-%s]\n",
                   ip_str, dport, ch->name, ch->category, ch->quality);
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

void make_group_title(const channel_t *ch, char *group) {
    sprintf(group, "%s-%s", ch->category, ch->quality);
}

// 辅助函数：根据前缀构造完整URL
void build_url(char *buf, size_t size, const char *prefix, const char *ip, int port) {
    if (strstr(prefix, "://") != NULL) {
        // 前缀已包含协议和路径，直接拼接IP:端口
        snprintf(buf, size, "%s%s:%d", prefix, ip, port);
    } else {
        // 前缀视为协议名，构造 protocol://ip:port
        snprintf(buf, size, "%s://%s:%d", prefix, ip, port);
    }
}

void write_outputs(const char *base_m3u_path) {
    char m3u_path[256], m3u_hd_path[256], txt_path[256];
    strncpy(m3u_path, base_m3u_path, 255);
    m3u_path[255] = '\0';

    char *dot = strrchr(m3u_path, '.');
    if (dot && strcmp(dot, ".m3u") == 0) {
        size_t pos = dot - m3u_path;
        strncpy(m3u_hd_path, m3u_path, pos);
        m3u_hd_path[pos] = '\0';
        strcat(m3u_hd_path, "_hd.m3u");
        strncpy(txt_path, m3u_path, pos);
        txt_path[pos] = '\0';
        strcat(txt_path, ".txt");
    } else {
        snprintf(m3u_hd_path, sizeof(m3u_hd_path), "%s_hd.m3u", m3u_path);
        snprintf(txt_path, sizeof(txt_path), "%s.txt", m3u_path);
    }

    FILE *f_m3u = fopen(m3u_path, "w");
    FILE *f_m3u_hd = fopen(m3u_hd_path, "w");
    FILE *f_txt = fopen(txt_path, "w");

    if (!f_m3u || !f_m3u_hd || !f_txt) {
        perror("无法创建输出文件");
        if (f_m3u) fclose(f_m3u);
        if (f_m3u_hd) fclose(f_m3u_hd);
        if (f_txt) fclose(f_txt);
        return;
    }

    // 写入M3U头部
    if (epg_url && strlen(epg_url) > 0) {
        fprintf(f_m3u, "#EXTM3U x-tvg-url=\"%s\"\n", epg_url);
        fprintf(f_m3u_hd, "#EXTM3U x-tvg-url=\"%s\"\n", epg_url);
    } else {
        fprintf(f_m3u, "#EXTM3U\n");
        fprintf(f_m3u_hd, "#EXTM3U\n");
    }

    char group[64];
    char tvg_name_attr[128];
    char logo_attr[128];
    char url[512];

    // 先排序
    for (int i = 0; i < channel_count-1; i++) {
        for (int j = i+1; j < channel_count; j++) {
            char group_i[64], group_j[64];
            make_group_title(&channels[i], group_i);
            make_group_title(&channels[j], group_j);
            int cmp = strcmp(group_i, group_j);
            if (cmp > 0) {
                channel_t tmp = channels[i];
                channels[i] = channels[j];
                channels[j] = tmp;
            } else if (cmp == 0) {
                if (strcmp(channels[i].name, channels[j].name) > 0) {
                    channel_t tmp = channels[i];
                    channels[i] = channels[j];
                    channels[j] = tmp;
                }
            }
        }
    }

    for (int i = 0; i < channel_count; i++) {
        channel_t *ch = &channels[i];
        make_group_title(ch, group);

        if (strlen(ch->pure_name) > 0)
            snprintf(tvg_name_attr, sizeof(tvg_name_attr), " tvg-name=\"%s\"", ch->pure_name);
        else
            tvg_name_attr[0] = '\0';

        if (logo_base && strlen(logo_base) > 0 && strlen(ch->pure_name) > 0) {
            snprintf(logo_attr, sizeof(logo_attr), " tvg-logo=\"%s/%s.png\"", logo_base, ch->pure_name);
        } else {
            logo_attr[0] = '\0';
        }

        // 构造播放URL（根据前缀格式）
        build_url(url, sizeof(url), play_prefix, ch->ip, ch->port);

        // 全量M3U
        fprintf(f_m3u, "#EXTINF:-1%s%s group-title=\"%s\",%s\n", tvg_name_attr, logo_attr, group, ch->name);
        fprintf(f_m3u, "%s\n", url);

        // 高清M3U
        if (strcmp(ch->quality, "标清") != 0) {
            char clean_name_hd[NAME_LEN];
            strncpy(clean_name_hd, ch->name, NAME_LEN-1);
            clean_name_hd[NAME_LEN-1] = '\0';
            char *p;
            while ((p = strstr(clean_name_hd, "高清")) != NULL) memmove(p, p+6, strlen(p+6)+1);
            while ((p = strstr(clean_name_hd, "HD")) != NULL) memmove(p, p+2, strlen(p+2)+1);
            char *start = clean_name_hd;
            while (*start == ' ') start++;
            char *end = start + strlen(start) - 1;
            while (end > start && (*end == ' ')) *end-- = '\0';

            fprintf(f_m3u_hd, "#EXTINF:-1%s%s group-title=\"%s\",%s\n", tvg_name_attr, logo_attr, ch->category, start);
            fprintf(f_m3u_hd, "%s\n", url);
        }
    }

    // TXT文件
    char last_group[64] = "";
    for (int i = 0; i < channel_count; i++) {
        channel_t *ch = &channels[i];
        char group[64];
        make_group_title(ch, group);
        if (strcmp(group, last_group) != 0) {
            fprintf(f_txt, "\n%s,#genre#\n", group);
            strcpy(last_group, group);
        }
        // 重新构造URL（也可复用之前的url，但需注意变量作用域）
        build_url(url, sizeof(url), play_prefix, ch->ip, ch->port);
        fprintf(f_txt, "%s,%s\n", ch->name, url);
    }

    fclose(f_m3u);
    fclose(f_m3u_hd);
    fclose(f_txt);

    printf("\n[*] 输出文件:\n");
    printf("    全量M3U: %s\n", m3u_path);
    printf("    高清M3U: %s\n", m3u_hd_path);
    printf("    TXT列表: %s\n", txt_path);
}

int main(int argc, char *argv[]) {
    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"epg",    required_argument, 0, 'e'},
        {"logo",   required_argument, 0, 'l'},
        {"prefix", required_argument, 0, 'p'},
        {"dict",   required_argument, 0, 'd'},
        {"city",   required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    // 临时保存用户指定的路径（来自命令行）
    const char *user_dict = NULL;
    const char *user_city = NULL;

    while ((opt = getopt_long(argc, argv, "e:l:p:d:c:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'e':
                epg_url = optarg;
                break;
            case 'l':
                logo_base = optarg;
                break;
            case 'p':
                play_prefix = optarg;
                break;
            case 'd':
                user_dict = optarg;
                break;
            case 'c':
                user_city = optarg;
                break;
            default:
                fprintf(stderr, "用法: %s [选项] <网卡> <M3U保存路径> <等待秒数> <网段前缀1> [网段2...]\n", argv[0]);
                fprintf(stderr, "选项:\n");
                fprintf(stderr, "  -e, --epg URL        设置EPG地址\n");
                fprintf(stderr, "  -l, --logo PATH      设置Logo基础路径\n");
                fprintf(stderr, "  -p, --prefix PREFIX  设置播放前缀 (默认: rtp，也可指定完整URL前缀如 http://192.168.1.1:4022/udp/ )\n");
                fprintf(stderr, "  -d, --dict PATH      设置字典文件路径\n");
                fprintf(stderr, "  -c, --city PATH      设置城市列表文件路径\n");
                return 1;
        }
    }

    if (argc - optind < 4) {
        fprintf(stderr, "错误: 缺少必要的参数\n");
        fprintf(stderr, "用法: %s [选项] <网卡> <M3U保存路径> <等待秒数> <网段前缀1> [网段2...]\n", argv[0]);
        return 1;
    }

    char *dev = argv[optind];
    char *save_path = argv[optind + 1];
    g_wait_time = atoi(argv[optind + 2]);

    // --- 确定字典文件路径 ---
    if (user_dict) {
        dict_path = user_dict;
    } else {
        const char *env_dict = getenv("IPTV_DICT");
        if (env_dict) {
            dict_path = env_dict;
        } else {
            dict_path = "/root/iptv_dict.txt";
        }
    }

    // --- 确定城市列表文件路径 ---
    if (user_city) {
        city_path = user_city;
    } else {
        const char *env_city = getenv("IPTV_CITY");
        if (env_city) {
            city_path = env_city;
        } else {
            city_path = "/root/city_list.txt";
        }
    }

    // --- 确定EPG和Logo（若命令行未提供，尝试环境变量）---
    if (strlen(epg_url) == 0) {
        const char *env_epg = getenv("IPTV_EPG");
        if (env_epg) epg_url = env_epg;
    }
    if (strlen(logo_base) == 0) {
        const char *env_logo = getenv("IPTV_LOGO");
        if (env_logo) logo_base = env_logo;
    }
    // play_prefix 已经设置，若需要可从环境变量覆盖，此处暂不处理

    // 加载字典和城市列表
    load_dict(dict_path);
    load_cities(city_path);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(dev, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_create 失败: %s\n", errbuf);
        return 1;
    }
    pcap_set_snaplen(handle, 128);
    pcap_set_timeout(handle, 100);
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "无法激活网卡: %s\n", pcap_geterr(handle));
        return 1;
    }

    setup_link_offset(handle);
    
    printf("[*] 环境就绪: 链路类型 %s, 偏移 %d 字节\n",
           pcap_datalink_val_to_name(pcap_datalink(handle)), g_link_offset);
    printf("[*] 开始扫描，仅显示成功发现频道的结果...\n");
    printf("----------------------------------------------------\n");

    for (int arg_idx = optind + 3; arg_idx < argc; arg_idx++) {
        char *prefix = argv[arg_idx];
        memset(global_found, 0, sizeof(global_found));
        for (int i = 1; i <= 254; i++) {
            scan_single_ip(handle, prefix, i);
        }
    }

    printf("----------------------------------------------------\n");
    printf("[*] 扫描完成！共发现 %d 个频道\n", channel_count);

    if (channel_count > 0) {
        write_outputs(save_path);
    } else {
        printf("[*] 未发现任何频道，无输出文件生成。\n");
    }

    pcap_close(handle);
    return 0;
}
