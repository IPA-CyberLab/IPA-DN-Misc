/*
 * etherip.h - EtherIP (RFC3378) 仮想デバイスドライバヘッダファイル
 *
 * このファイルは EtherIP 仮想デバイスドライバの定義を含みます。
 */

#ifndef _ETHERIP_H_
#define _ETHERIP_H_

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <net/ip.h>
#include <net/ipv6.h>

/* EtherIP プロトコル番号 (RFC3378) */
#define IPPROTO_ETHERIP 97

/* EtherIP ヘッダバージョン (RFC3378) */
#define ETHERIP_VERSION 3

/* EtherIP ヘッダ構造体 */
struct etherip_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    reserved:4,
            version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            reserved:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    __u8    reserved2;
} __attribute__((packed));

/* EtherIP デバイスプライベートデータ構造体 */
struct etherip_dev {
    struct net_device *dev;              /* ネットワークデバイス */
    struct list_head list;               /* デバイスリスト用 */
    
    /* 設定パラメータ */
    union {
        struct in_addr ip4;              /* IPv4 宛先アドレス */
        struct in6_addr ip6;             /* IPv6 宛先アドレス */
    } dst_addr;
    int addr_family;                     /* AF_INET または AF_INET6 */
    u8 hw_addr[ETH_ALEN];               /* MAC アドレス */
    
    /* 統計情報 */
    struct net_device_stats stats;
    
    /* ロック */
    spinlock_t lock;
    
    /* procfs エントリ */
    struct proc_dir_entry *proc_entry;
};

/* procfs コントロールファイル名 */
#define ETHERIP_PROC_DIR "sys/net/etherip"
#define ETHERIP_PROC_CREATE "create"

/* デバイス名のプレフィックス */
#define ETHERIP_DEV_PREFIX "eip"

/* 最大デバイス数 */
#define ETHERIP_MAX_DEVS 256

/* 関数プロトタイプ */
int etherip_init(void);
void etherip_exit(void);

#endif /* _ETHERIP_H_ */