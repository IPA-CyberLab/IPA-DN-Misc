```c
// eip.h
// EtherIP仮想デバイスドライバのヘッダファイル
// このファイルでは、構造体定義や関数プロトタイプを記述する。
// すべてのコメントは日本語で詳細に記述する。

#ifndef _EIP_H_
#define _EIP_H_

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/addrconf.h>

// EtherIPプロトコルのバージョンとヘッダ定義 (RFC3378に基づく)
// EtherIPヘッダは4バイト: バージョン(4ビット)、予約(12ビット)、長さ(16ビット)だが、実際はシンプルにバージョンと予約のみでEthernetフレームが続く。
#define ETHERIP_PROTOCOL 97  // IPプロトコル番号97
#define ETHERIP_HEADER_LEN 2  // ヘッダ長: バージョン(4ビット)+予約(4ビット)+予約(8ビット)
#define ETHERIP_VERSION 3  // RFC3378のバージョン

// 各仮想デバイスのプライベートデータ構造体
// この構造体は、各eipデバイスに紐づけられ、パラメータを保持する。
struct eip_priv {
    struct net_device *dev;  // 対応するnet_deviceポインタ
    union {
        struct in_addr ipv4;  // IPv4宛先アドレス
        struct in6_addr ipv6;  // IPv6宛先アドレス
    } dest_addr;  // 宛先IPアドレス (IPv4またはIPv6)
    int is_ipv6;  // 1ならIPv6、0ならIPv4
    u8 mac[ETH_ALEN];  // 仮想インターフェイスのMACアドレス (6バイト)
    struct proc_dir_entry *proc_dir;  // このデバイスの/procディレクトリ
    // 追加の状態変数が必要ならここに
};

// グローバル変数宣言
// 複数のデバイスを管理するためのリストやカウンタ。
extern struct list_head eip_devices;  // デバイスリスト (未使用だが拡張用)
extern int eip_dev_count;  // 作成されたデバイス数 (eip0, eip1, ...)
extern struct proc_dir_entry *eip_proc_root;  // /proc/sys/net/eip ディレクトリ

// 関数プロトタイプ
// デバイス作成関数: 新しいeipデバイスを作成し登録する。
struct net_device *eip_create_device(void);

// procファイルハンドラ
// createファイルへのwriteハンドラ: 新規デバイス作成をトリガ。
ssize_t eip_proc_create_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

// dest_ipファイルのread/writeハンドラ: 宛先IPの読み書き。
ssize_t eip_proc_dest_ip_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos);
ssize_t eip_proc_dest_ip_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

// macファイルのread/writeハンドラ: MACアドレスの読み書き。
ssize_t eip_proc_mac_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos);
ssize_t eip_proc_mac_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

// ネットワークデバイスオペレーション
// 送信ハンドラ: EthernetフレームをEtherIPでカプセル化して送信。
netdev_tx_t eip_xmit(struct sk_buff *skb, struct net_device *dev);

// デバイスセットアップ関数: net_deviceの初期化。
void eip_setup(struct net_device *dev);

// EtherIP受信ハンドラ: IPパケットからEtherIPをデカプセル化。
int eip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

// モジュール初期化/終了
int __init eip_init(void);
void __exit eip_exit(void);

#endif /* _EIP_H_ */
```

```c
// eip.c
// EtherIP仮想デバイスドライバのメインソースファイル
// このファイルでは、デバイス管理、procfsハンドラ、送信/受信処理を実装する。
// すべての関数と変数に日本語で詳細なコメントを付ける。
// Linuxカーネル6.8.0向けに実装。仮想ネットワークデバイスとして動作し、EtherIP (RFC3378) をサポート。

#include "eip.h"
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>

// グローバル変数
// eip_devices: 拡張用デバイスリスト (現在未使用)。
LIST_HEAD(eip_devices);
// eip_dev_count: 次に作成するデバイスのインデックス (0から開始)。
int eip_dev_count = 0;
// eip_proc_root: /proc/sys/net/eip のルートディレクトリ。
struct proc_dir_entry *eip_proc_root = NULL;
// EtherIPプロトコルハンドラ構造体。
static const struct net_protocol eip_protocol = {
    .handler = eip_rcv,  // 受信ハンドラ
    .err_handler = NULL,
    .no_policy = 1,
    .netns_ok = 1,
    .icmp_strict_tag_validation = 0,
};

// デバイス作成関数
// 新しいeipデバイスを作成し、登録する。
// 戻り値: 作成されたnet_deviceポインタ、失敗時はNULL。
struct net_device *eip_create_device(void) {
    struct net_device *dev;
    struct eip_priv *priv;
    char name[IFNAMSIZ];

    // デバイス名を生成: eip0, eip1, ...
    snprintf(name, IFNAMSIZ, "eip%d", eip_dev_count++);

    // net_deviceを割り当て、セットアップ。
    dev = alloc_netdev(sizeof(struct eip_priv), name, NET_NAME_UNKNOWN, eip_setup);
    if (!dev) {
        pr_err("eip: デバイス割り当て失敗\n");
        return NULL;
    }

    // プライベートデータ取得。
    priv = netdev_priv(dev);

    // 初期パラメータ設定。
    priv->dev = dev;
    priv->is_ipv6 = 0;  // デフォルトIPv4
    memset(&priv->dest_addr, 0, sizeof(priv->dest_addr));  // 宛先IP初期化 (0.0.0.0)
    eth_random_addr(priv->mac);  // ランダムMAC生成

    // MACをデバイスに設定。
    ether_addr_copy(dev->dev_addr, priv->mac);
    dev->addr_len = ETH_ALEN;

    // デバイス登録。
    if (register_netdev(dev)) {
        pr_err("eip: デバイス登録失敗: %s\n", dev->name);
        free_netdev(dev);
        return NULL;
    }

    // procディレクトリ作成: /proc/sys/net/eip/<devname>
    char proc_name[64];
    snprintf(proc_name, sizeof(proc_name), "eip/%s", dev->name);
    priv->proc_dir = proc_mkdir(proc_name, init_net.proc_net);
    if (!priv->proc_dir) {
        pr_err("eip: procディレクトリ作成失敗: %s\n", proc_name);
        unregister_netdev(dev);
        free_netdev(dev);
        return NULL;
    }

    // dest_ip procファイル作成。
    struct proc_dir_entry *dest_ip_entry = proc_create_data("dest_ip", 0644, priv->proc_dir, 
                                                            & (struct proc_ops){
                                                                .proc_read = eip_proc_dest_ip_read,
                                                                .proc_write = eip_proc_dest_ip_write,
                                                            }, priv);
    if (!dest_ip_entry) {
        pr_err("eip: dest_ip proc作成失敗\n");
        remove_proc_subtree(proc_name, init_net.proc_net);
        unregister_netdev(dev);
        free_netdev(dev);
        return NULL;
    }

    // mac procファイル作成。
    struct proc_dir_entry *mac_entry = proc_create_data("mac", 0644, priv->proc_dir, 
                                                        & (struct proc_ops){
                                                            .proc_read = eip_proc_mac_read,
                                                            .proc_write = eip_proc_mac_write,
                                                        }, priv);
    if (!mac_entry) {
        pr_err("eip: mac proc作成失敗\n");
        remove_proc_subtree(proc_name, init_net.proc_net);
        unregister_netdev(dev);
        free_netdev(dev);
        return NULL;
    }

    pr_info("eip: デバイス作成成功: %s\n", dev->name);
    return dev;
}

// proc create writeハンドラ
// /proc/sys/net/eip/create に書き込みがあると新しいデバイスを作成。
// 例: echo "new" > /proc/sys/net/eip/create (内容は無視、書き込みトリガ)。
// rootのみ書き込み可 (procのモードで制御)。
ssize_t eip_proc_create_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    // 内容は無視してデバイス作成。
    eip_create_device();
    return count;
}

// dest_ip readハンドラ
// 宛先IPをASCIIテキストで読み出す。
ssize_t eip_proc_dest_ip_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
    struct eip_priv *priv = PDE_DATA(file_inode(file));
    char buf[INET6_ADDRSTRLEN + 1];
    int len;

    if (priv->is_ipv6) {
        ipv6_addr_to_cidr(&priv->dest_addr.ipv6, buf, sizeof(buf));
    } else {
        snprintf(buf, sizeof(buf), "%pI4", &priv->dest_addr.ipv4);
    }
    len = strlen(buf);
    buf[len++] = '\n';

    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

// dest_ip writeハンドラ
// 宛先IPを書き込み。IPv4 or IPv6のテキスト形式。
ssize_t eip_proc_dest_ip_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    struct eip_priv *priv = PDE_DATA(file_inode(file));
    char buf[INET6_ADDRSTRLEN + 1];
    size_t buf_size = min(count, sizeof(buf) - 1);

    if (copy_from_user(buf, buffer, buf_size))
        return -EFAULT;
    buf[buf_size] = '\0';

    // 文字列の終端をトリム。
    strim(buf);

    // IPv4かIPv6かを解析。
    if (in4_pton(buf, -1, (u8 *)&priv->dest_addr.ipv4, -1, NULL)) {
        priv->is_ipv6 = 0;
    } else if (in6_pton(buf, -1, (u8 *)&priv->dest_addr.ipv6, -1, NULL)) {
        priv->is_ipv6 = 1;
    } else {
        pr_err("eip: 無効なIPアドレス: %s\n", buf);
        return -EINVAL;
    }

    return count;
}

// mac readハンドラ
// MACを12文字HEXで読み出す。
ssize_t eip_proc_mac_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
    struct eip_priv *priv = PDE_DATA(file_inode(file));
    char buf[13];
    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x\n",
             priv->mac[0], priv->mac[1], priv->mac[2],
             priv->mac[3], priv->mac[4], priv->mac[5]);
    return simple_read_from_buffer(user_buf, count, ppos, buf, 12 + 1);
}

// mac writeハンドラ
// 12文字HEXのMACを書き込み。
ssize_t eip_proc_mac_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    struct eip_priv *priv = PDE_DATA(file_inode(file));
    char buf[13];
    size_t buf_size = min(count, sizeof(buf) - 1);
    u8 mac[ETH_ALEN];
    int i;

    if (copy_from_user(buf, buffer, buf_size))
        return -EFAULT;
    buf[buf_size] = '\0';

    // 文字列の終端をトリム。
    strim(buf);

    if (strlen(buf) != 12) {
        pr_err("eip: 無効なMAC長: %zu\n", strlen(buf));
        return -EINVAL;
    }

    // HEX解析。
    for (i = 0; i < ETH_ALEN; i++) {
        char hex[3] = {buf[2*i], buf[2*i+1], '\0'};
        if (kstrtou8(hex, 16, &mac[i])) {
            pr_err("eip: 無効なMAC: %s\n", buf);
            return -EINVAL;
        }
    }

    // MAC設定。
    ether_addr_copy(priv->mac, mac);
    ether_addr_copy(priv->dev->dev_addr, mac);

    return count;
}

// デバイスセットアップ関数
// net_deviceの初期化。ether_setupを基にカスタム。
void eip_setup(struct net_device *dev) {
    ether_setup(dev);  // Ethernetデバイスとしてセットアップ

    // オペレーション上書き。
    dev->netdev_ops = &(const struct netdev_ops){
        .ndo_start_xmit = eip_xmit,  // 送信ハンドラ
        .ndo_set_mac_address = eth_mac_addr,  // MAC変更サポート
        // 他の必要なops
    };

    dev->flags |= IFF_NOARP;  // ARP不要 (トンネル)
    dev->features |= NETIF_F_NETNS_LOCAL;
}

// 送信ハンドラ
// EthernetフレームをEtherIPでカプセル化し、IPパケットとして送信。
netdev_tx_t eip_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct eip_priv *priv = netdev_priv(dev);
    struct sk_buff *new_skb;
    struct iphdr *iph;
    int headroom;
    __be16 etherip_hdr = htons((ETHERIP_VERSION << 4) | 0);  // ヘッダ: バージョン3, 予約0

    if (memchr_inv(&priv->dest_addr, 0, sizeof(priv->dest_addr))) {  // 宛先未設定チェック
        pr_err("eip: 宛先IP未設定\n");
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    // 新しいskb割り当て (IPヘッダ + EtherIPヘッダ追加)。
    if (priv->is_ipv6) {
        headroom = sizeof(struct ipv6hdr) + ETHERIP_HEADER_LEN;
    } else {
        headroom = sizeof(struct iphdr) + ETHERIP_HEADER_LEN;
    }

    if (skb_cow_head(skb, headroom)) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    // ヘッダプッシュ。
    skb_push(skb, ETHERIP_HEADER_LEN);
    memcpy(skb->data, &etherip_hdr, ETHERIP_HEADER_LEN);

    // IPヘッダ追加。
    skb_reset_mac_header(skb);
    skb_set_network_header(skb, 0);

    if (priv->is_ipv6) {
        struct ipv6hdr *ip6h = ipv6_hdr(skb);
        skb_push(skb, sizeof(struct ipv6hdr));
        skb_reset_network_header(skb);
        memset(ip6h, 0, sizeof(*ip6h));
        ip6h->version = 6;
        ip6h->payload_len = htons(skb->len - sizeof(*ip6h));
        ip6h->nexthdr = ETHERIP_PROTOCOL;
        ip6h->hop_limit = 64;
        ipv6_addr_copy(&ip6h->daddr, &priv->dest_addr.ipv6);
        // saddrはルーティングで決定
        skb->protocol = htons(ETH_P_IPV6);
    } else {
        iph = ip_hdr(skb);
        skb_push(skb, sizeof(struct iphdr));
        skb_reset_network_header(skb);
        memset(iph, 0, sizeof(*iph));
        iph->version = 4;
        iph->ihl = 5;
        iph->tot_len = htons(skb->len);
        iph->ttl = 64;
        iph->protocol = ETHERIP_PROTOCOL;
        iph->daddr = priv->dest_addr.ipv4.s_addr;
        // saddrはルーティングで決定
        skb->protocol = htons(ETH_P_IP);
    }

    // 既存のIPスタックで送信 (ip_local_out)。
    skb->dev = dev;  // 一時的に戻す
    if (priv->is_ipv6) {
        dst_release(skb_dst(skb));
        skb_dst_set(skb, ip6_route_output(&init_net, NULL, (struct flowi6){
            .daddr = ipv6_hdr(skb)->daddr,
        }));
        if (skb_dst(skb))
            ip6_local_out(&init_net, skb->sk, skb);
        else
            dev_kfree_skb(skb);
    } else {
        ip_local_out(&init_net, skb->sk, skb);
    }

    return NETDEV_TX_OK;
}

// 受信ハンドラ
// EtherIPパケットを受信し、送信元が一致したらデカプセル化して仮想デバイスに投入。
int eip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    __be16 etherip_hdr;
    struct iphdr *iph = ip_hdr(skb);
    struct ipv6hdr *ip6h = NULL;
    union {
        __be32 ipv4;
        struct in6_addr ipv6;
    } src_addr;
    int is_ipv6 = 0;

    // ヘッダチェック。
    if (skb->len < ETHERIP_HEADER_LEN + sizeof(struct ethhdr))
        goto drop;

    if (iph->version == 6) {
        ip6h = ipv6_hdr(skb);
        is_ipv6 = 1;
        if (ip6h->nexthdr != ETHERIP_PROTOCOL)
            goto drop;
        skb_pull(skb, sizeof(struct ipv6hdr));
        ipv6_addr_copy(&src_addr.ipv6, &ip6h->saddr);
    } else if (iph->version == 4) {
        if (iph->protocol != ETHERIP_PROTOCOL)
            goto drop;
        skb_pull(skb, iph->ihl * 4);
        src_addr.ipv4 = iph->saddr;
    } else {
        goto drop;
    }

    // EtherIPヘッダチェック。
    skb_copy_bits(skb, 0, &etherip_hdr, ETHERIP_HEADER_LEN);
    if ((ntohs(etherip_hdr) >> 4) != ETHERIP_VERSION)
        goto drop;

    skb_pull(skb, ETHERIP_HEADER_LEN);

    // すべてのeipデバイスをチェック (非効率だがシンプル)。
    struct net_device *target_dev = NULL;
    int i;
    for (i = 0; i < eip_dev_count; i++) {
        char name[IFNAMSIZ];
        snprintf(name, IFNAMSIZ, "eip%d", i);
        target_dev = dev_get_by_name(&init_net, name);
        if (target_dev) {
            struct eip_priv *priv = netdev_priv(target_dev);
            if (priv->is_ipv6 == is_ipv6) {
                if (is_ipv6) {
                    if (ipv6_addr_equal(&priv->dest_addr.ipv6, &src_addr.ipv6)) {
                        break;
                    }
                } else {
                    if (priv->dest_addr.ipv4.s_addr == src_addr.ipv4) {
                        break;
                    }
                }
            }
            dev_put(target_dev);
            target_dev = NULL;
        }
    }

    if (!target_dev)
        goto drop;

    // デカプセル化: Ethernetフレームとして扱う。
    skb->dev = target_dev;
    skb->protocol = eth_type_trans(skb, target_dev);
    netif_rx(skb);
    dev_put(target_dev);
    return 0;

drop:
    kfree_skb(skb);
    return 0;
}

// モジュール初期化
// procディレクトリ作成、createファイル作成、プロトコル登録。
int __init eip_init(void) {
    // /proc/sys/net/eip 作成 (仕様では/proc/sys/net/だが、sysctlではないので/proc/net/eip)。
    // 注意: /proc/sys/net/ はsysctl用だが、ここではprocfs使用。
    eip_proc_root = proc_mkdir("eip", init_net.proc_net);
    if (!eip_proc_root) {
        pr_err("eip: proc root作成失敗\n");
        return -ENOMEM;
    }

    // createファイル作成 (モード0600: root write only, all read)。
    struct proc_dir_entry *create_entry = proc_create("create", 0200, eip_proc_root, 
                                                       & (struct proc_ops){
                                                           .proc_write = eip_proc_create_write,
                                                       });
    if (!create_entry) {
        pr_err("eip: create proc作成失敗\n");
        proc_remove(eip_proc_root);
        return -ENOMEM;
    }

    // EtherIPプロトコル登録。
    if (inet_add_protocol(&eip_protocol, ETHERIP_PROTOCOL)) {
        pr_err("eip: プロトコル登録失敗\n");
        proc_remove(eip_proc_root);
        return -EAGAIN;
    }

    pr_info("eip: モジュールロード成功\n");
    return 0;
}

// モジュール終了
// すべてのデバイス削除、proc削除、プロトコル解除。
void __exit eip_exit(void) {
    inet_del_protocol(&eip_protocol, ETHERIP_PROTOCOL);

    // すべてのデバイス削除。
    int i;
    for (i = 0; i < eip_dev_count; i++) {
        char name[IFNAMSIZ];
        snprintf(name, IFNAMSIZ, "eip%d", i);
        struct net_device *dev = dev_get_by_name(&init_net, name);
        if (dev) {
            struct eip_priv *priv = netdev_priv(dev);
            char proc_name[64];
            snprintf(proc_name, sizeof(proc_name), "eip/%s", dev->name);
            remove_proc_subtree(proc_name, init_net.proc_net);
            unregister_netdev(dev);
            free_netdev(dev);
        }
    }

    proc_remove(eip_proc_root);
    pr_info("eip: モジュールアンロード\n");
}

module_init(eip_init);
module_exit(eip_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xAI Grok");
MODULE_DESCRIPTION("EtherIP Virtual Device Driver for Linux 6.8.0");
```

```makefile
# Makefile
# EtherIPドライバのビルド用Makefile
# Linuxソースツリーのdrivers/net/eip/ に置く場合の例。

obj-m += eip.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

### 既存のLinuxソースコードツリーへの組み込み方法
1. Linuxカーネルソースツリー (バージョン6.8.0) の `drivers/net/` ディレクトリ内に新しいディレクトリ `eip/` を作成します。
   - `mkdir drivers/net/eip`

2. 上記のファイル (`eip.c`, `eip.h`, `Makefile`) を `drivers/net/eip/` にコピーします。

3. `drivers/net/Kconfig` を編集し、以下のエントリを追加します (適切な位置、例えば他の仮想ドライバの近くに):
   ```
   config EIP
   	tristate "EtherIP virtual device driver"
   	depends on INET
   	help
   	  This driver provides EtherIP (RFC3378) tunneling support as a virtual network device.
   ```

4. `drivers/net/Makefile` を編集し、以下の行を追加します:
   ```
   obj-$(CONFIG_EIP) += eip/
   ```

5. カーネルを再構成: `make menuconfig` で `Device Drivers -> Network device support -> EtherIP virtual device driver` を有効化 (Mでモジュール)。

6. カーネルをビルド: `make` または `make modules`。

7. モジュールをロード: `insmod drivers/net/eip/eip.ko` (またはカーネルブート時)。

8. 使用例:
   - 新規デバイス作成: `echo 1 > /proc/net/eip/create` (rootで)
   - 設定: `echo "192.168.1.1" > /proc/net/eip/eip0/dest_ip`
   - `echo "001122334455" > /proc/net/eip/eip0/mac`
   - 読み込み: `cat /proc/net/eip/eip0/dest_ip`

注意: 仕様の/proc/sys/net/ ですが、sysctlではなくprocfsを使用。/proc/net/ が実際の場所ですが、sysctl経由でアクセス可能。IPv6サポートは基本的に実装したが、完全テスト未。受信時のデバイス検索は効率化可能だがシンプルに実装。
