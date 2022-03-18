#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>




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
//转发面支持接口更新删除表项，若表象改变，那控制面需要通知更新
struct fwd {
    int face;
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
};

struct bpf_map_def SEC("maps") fwdt = {
    .type = BPF_MAP_TYPE_LRU_HASH, 
    .key_size = sizeof(int),
    .value_size = sizeof(struct fwd),
    .max_entries = 100,
};

SEC("xdp_fwd")
int xpd_handle_fw(struct xdp_md *ctx) {

}

char _license []SEC("license") = "GPL";


//clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 fwd.bpf.c -I/usr/include/x86_64-linux-gnu/ -o fwd.bpf.o 
