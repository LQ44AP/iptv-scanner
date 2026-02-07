全量盲扫 (239.0.0.x - 239.255.255.x)

用法: iptv_scanner <网卡> <M3U保存路径> <等待秒> 

示例: iptv_scanner lan1 /tmp/iptv.m3u 1




扫不到请尝试：

添加路由表：route add -net 224.0.0.0 netmask 240.0.0.0 dev lan1

强制 IGMP V2：echo 2 > /proc/sys/net/ipv4/conf/lan1/force_igmp_version
