#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include <string.h>

//基于eBPF/XDP实现网络数据报的快速转发。传统网络转发逻辑
//
// 网络报文-->网卡-->内核查路由表-->下一跳
// [sip, dip, smac, dmac]           [sip, dip, smac1, dmac1]
//
//加速网路转发, 将dip的转发表存储eBPF Map, 转发时直接查表，不存在时再查询内核路由表
//
// xpd 查询内核路由通过 bpf_fib_lookup 函数
// 
// BPF_MAP_TYPE_LRU_HASH
// dip   uint32  目的IP     IPv4
// smac  uint64  转发源Mac
// dmac  uint64  转发目Mac
// iface uint32  从哪个设备发包
//
//eg:
//    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
//        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
//        inet 127.0.0.1/8 scope host lo
//           valid_lft forever preferred_lft forever
//        inet6 ::1/128 scope host 
//           valid_lft forever preferred_lft forever
//    2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
//        link/ether 08:00:27:f0:1e:41 brd ff:ff:ff:ff:ff:ff
//        inet 10.10.2.4/24 brd 10.10.2.255 scope global dynamic enp0s3
//           valid_lft 445sec preferred_lft 445sec
//        inet6 fe80::a00:27ff:fef0:1e41/64 scope link 
//           valid_lft forever preferred_lft forever
//    3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
//        link/ether 08:00:27:f3:81:0e brd ff:ff:ff:ff:ff:ff
//        inet 192.168.56.4/24 brd 192.168.56.255 scope global enp0s8
//           valid_lft forever preferred_lft forever
//        inet6 fe80::a00:27ff:fef3:810e/64 scope link 
//           valid_lft forever preferred_lft forever
//转发面支持接口更新删除表项，若表象改变，那控制面需要通知更新
//
// /usr/include/asm-generic/int-ll64.h 
struct fwd {
    __u32         ifindex;
    unsigned char smac[ETH_ALEN];
    unsigned char dmac[ETH_ALEN];
};

struct {
   __uint(type, BPF_MAP_TYPE_LRU_HASH);
   __type(key,          0x04);
   __type(value,        0x10);
   __uint(max_entries,  10000);
} hfwd SEC(".maps"); 

static __inline void  ipv4_decrease_ttl(struct iphdr *iph)
{
	__u32 check  = (__u32)iph->check;
	check       += (__u32)bpf_htons(0x0100);
	iph->check   = (__sum16)(check + (check >= 0xFFFF));
	--iph->ttl;
}

static __inline __u8 fast_fwd(struct fwd *elem, struct iphdr* iph) {
    struct fwd* item = (struct fwd *)bpf_map_lookup_elem(&hfwd, &iph->daddr);
    if (!item) {
        return 0x01;
    }
    elem->ifindex = item->ifindex;
    memcpy(elem->dmac, item->dmac, ETH_ALEN);
    memcpy(elem->smac, item->smac, ETH_ALEN);

    ipv4_decrease_ttl(iph);

    bpf_printk("fast fwd dstIp=%x",iph->daddr); 
    return 0x0;
}

static __inline __u8 slow_fwd(struct fwd *elem, struct xdp_md *ctx, struct iphdr* iph) {
	struct bpf_fib_lookup fib_params;

    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    fib_params.family	    = AF_INET;
	fib_params.tos		    = iph->tos;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.sport	    = 0;
	fib_params.dport	    = 0;
	fib_params.tot_len	    = bpf_ntohs(iph->tot_len);
	fib_params.ipv4_src	    = iph->saddr;
	fib_params.ipv4_dst	    = iph->daddr;
    fib_params.ifindex      = ctx->ingress_ifindex;

    __u64 rc;

    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0); 
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
        bpf_printk("slow fwd fib lookup fail. rc=%x dst_ip=%x", rc, iph->daddr); 
        return 0x01;
    }

    elem->ifindex  = fib_params.ifindex;
    memcpy(elem->dmac, fib_params.dmac, ETH_ALEN);
	memcpy(elem->smac, fib_params.smac, ETH_ALEN);

    bpf_map_update_elem(&hfwd, &iph->daddr, elem, BPF_ANY);
    ipv4_decrease_ttl(iph);

    return 0x0;
}

//refer https://github.com/torvalds/linux/blob/master/samples/bpf/xdp_fwd_kern.c
SEC("xdp_fwd")
int xpd_handle_fwd(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    //1. 解析L2
    struct fwd            elem;
	struct ethhdr         *eth = data;  //L2
	struct iphdr          *iph;         //L3

    __u64 nh_off;
    __u16 h_proto;

    nh_off = (char*)(eth + 1) - (char*)eth;
    if (data + nh_off > data_end) {
        return XDP_DROP;
    }

    h_proto = eth->h_proto;  //L3 协议类型


    switch (h_proto) {
    case bpf_htons(ETH_P_IP):
        break;
    default:
        return XDP_PASS;
    }

    //2. 解析L3
    iph = data + nh_off;
    nh_off += (char*)(iph + 1) - (char*)iph;

    if (data + nh_off > data_end) {
        return XDP_DROP;
    }

    __u8 rc;
    //3. fast_fwd
    rc = fast_fwd(&elem, iph);
    if (!rc) {
        memcpy(eth->h_dest, elem.dmac, ETH_ALEN);
        memcpy(eth->h_source, elem.smac, ETH_ALEN);
        return bpf_redirect(elem.ifindex, 0);
    }
    //4. slow_fwd
    rc = slow_fwd(&elem, ctx, iph);
    if (!rc) {
        memcpy(eth->h_dest, elem.dmac, ETH_ALEN);
        memcpy(eth->h_source, elem.smac, ETH_ALEN);
        return bpf_redirect(elem.ifindex, 0);
    }

    return XDP_PASS;
}

char _license []SEC("license") = "GPL";


//clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 fwd.bpf.c -I/usr/include/x86_64-linux-gnu/ -o fwd.bpf.o 
