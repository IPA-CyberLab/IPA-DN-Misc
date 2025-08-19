/*
 * etherip.c - EtherIP (RFC3378) 仮想デバイスドライバ
 *
 * このモジュールは、EtherIP プロトコルを使用して Ethernet フレームを
 * IP パケット内にカプセル化する仮想ネットワークデバイスを実装します。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/protocol.h>

#include "etherip.h"

/* モジュール情報 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("EtherIP (RFC3378) Virtual Network Device Driver");
MODULE_VERSION("1.0");

/* グローバル変数 */
static LIST_HEAD(etherip_dev_list);     /* デバイスリスト */
static DEFINE_SPINLOCK(etherip_lock);   /* グローバルロック */
static struct proc_dir_entry *etherip_proc_dir; /* procfs ディレクトリ */
static int etherip_dev_count = 0;       /* デバイス数カウンタ */

/* EtherIP パケット受信ハンドラ */
static int etherip_rcv(struct sk_buff *skb)
{
    struct etherip_hdr *eih;
    struct etherip_dev *edev;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct ethhdr *eth;
    bool found = false;
    
    /* ヘッダの最小サイズをチェック */
    if (!pskb_may_pull(skb, sizeof(struct etherip_hdr)))
        goto drop;
    
    /* EtherIP ヘッダを取得 */
    eih = (struct etherip_hdr *)skb->data;
    
    /* バージョンチェック */
    if (eih->version != ETHERIP_VERSION)
        goto drop;
    
    /* EtherIP ヘッダをスキップ */
    skb_pull(skb, sizeof(struct etherip_hdr));
    
    /* Ethernet フレームの最小サイズをチェック */
    if (!pskb_may_pull(skb, ETH_HLEN))
        goto drop;
    
    /* 送信元アドレスに一致するデバイスを検索 */
    spin_lock(&etherip_lock);
    list_for_each_entry(edev, &etherip_dev_list, list) {
        if (ip_hdr(skb)->version == 4 && edev->addr_family == AF_INET) {
            iph = ip_hdr(skb);
            if (memcmp(&iph->saddr, &edev->dst_addr.ip4, sizeof(struct in_addr)) == 0) {
                found = true;
                break;
            }
        } else if (ip_hdr(skb)->version == 6 && edev->addr_family == AF_INET6) {
            ip6h = ipv6_hdr(skb);
            if (memcmp(&ip6h->saddr, &edev->dst_addr.ip6, sizeof(struct in6_addr)) == 0) {
                found = true;
                break;
            }
        }
    }
    spin_unlock(&etherip_lock);
    
    if (!found)
        goto drop;
    
    /* パケットをデバイスに関連付け */
    skb->dev = edev->dev;
    skb->protocol = eth_type_trans(skb, edev->dev);
    
    /* 統計情報を更新 */
    spin_lock(&edev->lock);
    edev->stats.rx_packets++;
    edev->stats.rx_bytes += skb->len;
    spin_unlock(&edev->lock);
    
    /* パケットをネットワークスタックに渡す */
    netif_rx(skb);
    return 0;
    
drop:
    kfree_skb(skb);
    return 0;
}

/* ネットワークデバイスのオープン */
static int etherip_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

/* ネットワークデバイスのクローズ */
static int etherip_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

/* パケット送信処理 */
static netdev_tx_t etherip_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct etherip_dev *edev = netdev_priv(dev);
    struct etherip_hdr *eih;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct sk_buff *new_skb;
    int headroom;
    int err;
    
    /* 必要なヘッドルームを計算 */
    headroom = sizeof(struct etherip_hdr);
    if (edev->addr_family == AF_INET)
        headroom += sizeof(struct iphdr);
    else
        headroom += sizeof(struct ipv6hdr);
    
    /* 新しい skb を割り当てるか、既存の skb を拡張 */
    if (skb_headroom(skb) < headroom || skb_shared(skb)) {
        new_skb = skb_realloc_headroom(skb, headroom);
        if (!new_skb) {
            dev_kfree_skb(skb);
            spin_lock(&edev->lock);
            edev->stats.tx_dropped++;
            spin_unlock(&edev->lock);
            return NETDEV_TX_OK;
        }
        if (skb->sk)
            skb_set_owner_w(new_skb, skb->sk);
        dev_kfree_skb(skb);
        skb = new_skb;
    }
    
    /* EtherIP ヘッダを追加 */
    eih = (struct etherip_hdr *)skb_push(skb, sizeof(struct etherip_hdr));
    eih->version = ETHERIP_VERSION;
    eih->reserved = 0;
    eih->reserved2 = 0;
    
    /* IP ヘッダを設定して送信 */
    if (edev->addr_family == AF_INET) {
        /* IPv4 */
        skb_reset_network_header(skb);
        skb_push(skb, sizeof(struct iphdr));
        skb_reset_network_header(skb);
        
        iph = ip_hdr(skb);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = 0;
        iph->tot_len = htons(skb->len);
        iph->id = 0;
        iph->frag_off = htons(IP_DF);
        iph->ttl = 64;
        iph->protocol = IPPROTO_ETHERIP;
        iph->saddr = 0; /* カーネルが設定 */
        iph->daddr = edev->dst_addr.ip4.s_addr;
        
        /* チェックサムはカーネルが計算 */
        err = ip_local_out(dev_net(dev), skb->sk, skb);
    } else {
        /* IPv6 */
        skb_reset_network_header(skb);
        skb_push(skb, sizeof(struct ipv6hdr));
        skb_reset_network_header(skb);
        
        ip6h = ipv6_hdr(skb);
        ip6h->version = 6;
        ip6h->priority = 0;
        memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
        ip6h->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
        ip6h->nexthdr = IPPROTO_ETHERIP;
        ip6h->hop_limit = 64;
        /* 送信元アドレスはカーネルが設定 */
        memcpy(&ip6h->daddr, &edev->dst_addr.ip6, sizeof(struct in6_addr));
        
        err = ip6_local_out(dev_net(dev), skb->sk, skb);
    }
    
    /* 統計情報を更新 */
    if (err == NET_XMIT_SUCCESS || err == NET_XMIT_CN) {
        spin_lock(&edev->lock);
        edev->stats.tx_packets++;
        edev->stats.tx_bytes += skb->len;
        spin_unlock(&edev->lock);
    } else {
        spin_lock(&edev->lock);
        edev->stats.tx_errors++;
        spin_unlock(&edev->lock);
    }
    
    return NETDEV_TX_OK;
}

/* 統計情報取得 */
static struct net_device_stats *etherip_get_stats(struct net_device *dev)
{
    struct etherip_dev *edev = netdev_priv(dev);
    return &edev->stats;
}

/* MAC アドレス設定 */
static int etherip_set_mac_address(struct net_device *dev, void *p)
{
    struct etherip_dev *edev = netdev_priv(dev);
    struct sockaddr *addr = p;
    
    if (!is_valid_ether_addr(addr->sa_data))
        return -EADDRNOTAVAIL;
    
    spin_lock(&edev->lock);
    memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
    memcpy(edev->hw_addr, addr->sa_data, ETH_ALEN);
    spin_unlock(&edev->lock);
    
    return 0;
}

/* ネットワークデバイス操作構造体 */
static const struct net_device_ops etherip_netdev_ops = {
    .ndo_open = etherip_open,
    .ndo_stop = etherip_stop,
    .ndo_start_xmit = etherip_xmit,
    .ndo_get_stats = etherip_get_stats,
    .ndo_set_mac_address = etherip_set_mac_address,
};

/* デバイス設定表示 (procfs) */
static int etherip_proc_show(struct seq_file *m, void *v)
{
    struct etherip_dev *edev = m->private;
    char addr_str[INET6_ADDRSTRLEN];
    
    spin_lock(&edev->lock);
    
    /* 宛先アドレスを表示 */
    if (edev->addr_family == AF_INET) {
        snprintf(addr_str, sizeof(addr_str), "%pI4", &edev->dst_addr.ip4);
        seq_printf(m, "dst_addr: %s\n", addr_str);
    } else if (edev->addr_family == AF_INET6) {
        snprintf(addr_str, sizeof(addr_str), "%pI6", &edev->dst_addr.ip6);
        seq_printf(m, "dst_addr: %s\n", addr_str);
    } else {
        seq_printf(m, "dst_addr: not set\n");
    }
    
    /* MAC アドレスを表示 */
    seq_printf(m, "hw_addr: %02x%02x%02x%02x%02x%02x\n",
               edev->hw_addr[0], edev->hw_addr[1], edev->hw_addr[2],
               edev->hw_addr[3], edev->hw_addr[4], edev->hw_addr[5]);
    
    spin_unlock(&edev->lock);
    
    return 0;
}

/* デバイス設定書き込み (procfs) */
static ssize_t etherip_proc_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    struct etherip_dev *edev = PDE_DATA(file_inode(file));
    char buf[256];
    char *cmd, *arg;
    
    if (count >= sizeof(buf))
        return -EINVAL;
    
    if (copy_from_user(buf, buffer, count))
        return -EFAULT;
    
    buf[count] = '\0';
    
    /* コマンドと引数を分離 */
    cmd = buf;
    arg = strchr(buf, ' ');
    if (arg) {
        *arg = '\0';
        arg++;
        /* 末尾の改行を削除 */
        arg[strcspn(arg, "\n")] = '\0';
    }
    
    spin_lock(&edev->lock);
    
    if (strcmp(cmd, "dst_addr") == 0 && arg) {
        /* 宛先アドレス設定 */
        struct in_addr ip4;
        struct in6_addr ip6;
        
        if (in4_pton(arg, -1, (u8 *)&ip4, -1, NULL)) {
            edev->dst_addr.ip4 = ip4;
            edev->addr_family = AF_INET;
        } else if (in6_pton(arg, -1, (u8 *)&ip6, -1, NULL)) {
            memcpy(&edev->dst_addr.ip6, &ip6, sizeof(struct in6_addr));
            edev->addr_family = AF_INET6;
        } else {
            spin_unlock(&edev->lock);
            return -EINVAL;
        }
    } else if (strcmp(cmd, "hw_addr") == 0 && arg) {
        /* MAC アドレス設定 */
        u8 mac[ETH_ALEN];
        int i;
        
        if (strlen(arg) != 12) {
            spin_unlock(&edev->lock);
            return -EINVAL;
        }
        
        for (i = 0; i < ETH_ALEN; i++) {
            unsigned int val;
            if (sscanf(arg + i * 2, "%2x", &val) != 1) {
                spin_unlock(&edev->lock);
                return -EINVAL;
            }
            mac[i] = val;
        }
        
        if (!is_valid_ether_addr(mac)) {
            spin_unlock(&edev->lock);
            return -EADDRNOTAVAIL;
        }
        
        memcpy(edev->hw_addr, mac, ETH_ALEN);
        memcpy(edev->dev->dev_addr, mac, ETH_ALEN);
    } else {
        spin_unlock(&edev->lock);
        return -EINVAL;
    }
    
    spin_unlock(&edev->lock);
    
    return count;
}

/* procfs ファイル操作 */
static int etherip_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, etherip_proc_show, PDE_DATA(inode));
}

static const struct proc_ops etherip_proc_fops = {
    .proc_open = etherip_proc_open,
    .proc_read = seq_read,
    .proc_write = etherip_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* 新しいデバイスを作成 */
static int etherip_create_device(void)
{
    struct net_device *dev;
    struct etherip_dev *edev;
    char name[IFNAMSIZ];
    int err;
    
    /* デバイス数制限チェック */
    if (etherip_dev_count >= ETHERIP_MAX_DEVS)
        return -ENOSPC;
    
    /* デバイス名を生成 */
    snprintf(name, IFNAMSIZ, "%s%d", ETHERIP_DEV_PREFIX, etherip_dev_count);
    
    /* ネットワークデバイスを割り当て */
    dev = alloc_etherdev(sizeof(struct etherip_dev));
    if (!dev)
        return -ENOMEM;
    
    /* デバイス名を設定 */
    strcpy(dev->name, name);
    
    /* プライベートデータを初期化 */
    edev = netdev_priv(dev);
    edev->dev = dev;
    spin_lock_init(&edev->lock);
    memset(&edev->stats, 0, sizeof(edev->stats));
    edev->addr_family = 0;
    
    /* デバイス操作を設定 */
    dev->netdev_ops = &etherip_netdev_ops;
    
    /* デバイスフラグを設定 */
    dev->flags = IFF_BROADCAST | IFF_MULTICAST;
    dev->features = NETIF_F_NO_CSUM;
    
    /* ランダムな MAC アドレスを生成 */
    eth_hw_addr_random(dev);
    memcpy(edev->hw_addr, dev->dev_addr, ETH_ALEN);
    
    /* デバイスを登録 */
    err = register_netdev(dev);
    if (err) {
        free_netdev(dev);
        return err;
    }
    
    /* procfs エントリを作成 */
    edev->proc_entry = proc_create_data(name, 0644, etherip_proc_dir,
                                        &etherip_proc_fops, edev);
    if (!edev->proc_entry) {
        unregister_netdev(dev);
        free_netdev(dev);
        return -ENOMEM;
    }
    
    /* デバイスリストに追加 */
    spin_lock(&etherip_lock);
    list_add(&edev->list, &etherip_dev_list);
    etherip_dev_count++;
    spin_unlock(&etherip_lock);
    
    printk(KERN_INFO "etherip: created device %s\n", name);
    
    return 0;
}

/* create ファイルへの書き込み処理 */
static ssize_t etherip_create_write(struct file *file, const char __user *buffer,
                                    size_t count, loff_t *pos)
{
    char buf[16];
    
    if (count >= sizeof(buf))
        return -EINVAL;
    
    if (copy_from_user(buf, buffer, count))
        return -EFAULT;
    
    buf[count] = '\0';
    
    /* "1" が書き込まれたら新しいデバイスを作成 */
    if (buf[0] == '1') {
        int err = etherip_create_device();
        if (err)
            return err;
    }
    
    return count;
}

/* create ファイル操作 */
static const struct proc_ops etherip_create_fops = {
    .proc_write = etherip_create_write,
};

/* EtherIP プロトコルハンドラ */
static const struct net_protocol etherip_protocol = {
    .handler = etherip_rcv,
    .no_policy = 1,
};

static const struct inet6_protocol etherip_protocol6 = {
    .handler = etherip_rcv,
    .flags = INET6_PROTO_NOPOLICY,
};

/* モジュール初期化 */
int __init etherip_init(void)
{
    int err;
    
    /* procfs ディレクトリを作成 */
    etherip_proc_dir = proc_mkdir(ETHERIP_PROC_DIR, NULL);
    if (!etherip_proc_dir) {
        printk(KERN_ERR "etherip: failed to create proc directory\n");
        return -ENOMEM;
    }
    
    /* create ファイルを作成 */
    if (!proc_create(ETHERIP_PROC_CREATE, 0200, etherip_proc_dir,
                     &etherip_create_fops)) {
        printk(KERN_ERR "etherip: failed to create proc file\n");
        proc_remove(etherip_proc_dir);
        return -ENOMEM;
    }
    
    /* EtherIP プロトコルハンドラを登録 */
    err = inet_add_protocol(&etherip_protocol, IPPROTO_ETHERIP);
    if (err) {
        printk(KERN_ERR "etherip: failed to register IPv4 protocol\n");
        proc_remove(etherip_proc_dir);
        return err;
    }
    
    err = inet6_add_protocol(&etherip_protocol6, IPPROTO_ETHERIP);
    if (err) {
        printk(KERN_ERR "etherip: failed to register IPv6 protocol\n");
        inet_del_protocol(&etherip_protocol, IPPROTO_ETHERIP);
        proc_remove(etherip_proc_dir);
        return err;
    }
    
    printk(KERN_INFO "etherip: module loaded\n");
    
    return 0;
}

/* モジュール終了処理 */
void __exit etherip_exit(void)
{
    struct etherip_dev *edev, *tmp;
    
    /* プロトコルハンドラを削除 */
    inet_del_protocol(&etherip_protocol, IPPROTO_ETHERIP);
    inet6_del_protocol(&etherip_protocol6, IPPROTO_ETHERIP);
    
    /* すべてのデバイスを削除 */
    spin_lock(&etherip_lock);
    list_for_each_entry_safe(edev, tmp, &etherip_dev_list, list) {
        list_del(&edev->list);
        spin_unlock(&etherip_lock);
        
        if (edev->proc_entry)
            proc_remove(edev->proc_entry);
        
        unregister_netdev(edev->dev);
        free_netdev(edev->dev);
        
        spin_lock(&etherip_lock);
    }
    spin_unlock(&etherip_lock);
    
    /* procfs ディレクトリを削除 */
    proc_remove(etherip_proc_dir);
    
    printk(KERN_INFO "etherip: module unloaded\n");
}

module_init(etherip_init);
module_exit(etherip_exit);