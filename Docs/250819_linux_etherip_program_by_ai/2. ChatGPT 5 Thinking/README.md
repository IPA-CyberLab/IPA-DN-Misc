了解です。Linux 6.8.0 向けの EtherIP (RFC 3378) 仮想デバイスドライバ（モジュール）一式を用意しました。
以下に C ソース、ヘッダ、Makefile（ツリー外ビルド用）、カーネルツリーへ組み込む際の Kconfig/Makefile 追記例、使い方をまとめてあります。**各ソースには日本語で詳細コメント**を入れています。

> ⚠️ 免責: これは教育目的の参照実装です。実運用ではセキュリティ（フィルタリング、ACL、キー管理）、エラーハンドリング、MTU 制御、名前空間対応、RCU/locking の最適化、offload/CSUM 周りの調整等を用途に応じて見直してください。

---

## 目次

* `eip/` ディレクトリ構成
* ビルド（ツリー外・既存ツリー内）
* 使い方（作成・設定・送受信の流れ）
* ソースコード一式

---

## ディレクトリ構成

```
eip/
├── Makefile               # ツリー外ビルド用
├── Kbuild                 # ツリー外ビルドでのオブジェクト指定
├── Kconfig                # カーネルツリーへ組み込む場合
├── eip.h                  # 共通ヘッダ
├── eip_main.c             # net_device 実装（作成/送信など）
├── eip_proto.c            # EtherIP 受信処理（IPv4/IPv6 ハンドラ）
└── eip_sysctl.c           # /proc/sys/net/eip/* の制御（作成・各種設定）
```

---

## ビルド方法

### 1) ツリー外ビルド（推奨・お手軽）

```bash
cd eip
make
sudo insmod eip.ko
# アンロード: sudo rmmod eip
```

> カーネルヘッダが `/lib/modules/$(uname -r)/build` にある前提です。

### 2) 既存の Linux ソースツリーへ組み込み

1. `drivers/net/eip/` を作成し、この `eip/` 以下のファイルを配置。
2. `drivers/net/Kconfig` に以下を追記（末尾など適当な位置）:

   ```none
   source "drivers/net/eip/Kconfig"
   ```
3. `drivers/net/Makefile` に以下を追記:

   ```make
   obj-$(CONFIG_EIP) += eip/
   ```
4. 本リポジトリの `Kconfig` を `drivers/net/eip/Kconfig` として置く。
5. `make menuconfig` で `Device Drivers -> Network device support -> EtherIP virtual device (eip)` を `m` などに設定。
6. ビルド:

   ```bash
   make -j$(nproc)
   sudo insmod drivers/net/eip/eip.ko
   ```

---

## 使い方

### インターフェイスの作成（要 root）

本モジュールは `/proc/sys/net/eip/create` への **書き込み**でデバイスを作成します。読み取りはヘルプを返します（誰でも可）。
作成時に **宛先 IP（IPv4/IPv6）** と **MAC アドレス（12 桁 16 進）** を指定します。`name=` を省略すると `eip%d` 採番。

```bash
# IPv4 例:
echo "add dst=192.0.2.10 mac=001122334455 name=eip0" | sudo tee /proc/sys/net/eip/create

# IPv6 例:
echo "add dst=2001:db8::1 mac=aabbccddeeff" | sudo tee /proc/sys/net/eip/create
```

成功すると `/proc/sys/net/eip/<name>/` に以下の制御ファイルが現れます（**root のみ書込可、誰でも読取可**）:

* `/proc/sys/net/eip/eipX/peer` … 宛先 IP（ASCII）
* `/proc/sys/net/eip/eipX/mac`  … MAC（12 桁 HEX、例: `001122334455`）

> 例:
>
> ```bash
> cat /proc/sys/net/eip/eip0/peer
> cat /proc/sys/net/eip/eip0/mac
> echo "198.51.100.77" | sudo tee /proc/sys/net/eip/eip0/peer
> echo "deadbeefcafe" | sudo tee /proc/sys/net/eip/eip0/mac
> ```

### Link up / IP 設定など

```bash
sudo ip link set eip0 up
# L2 トンネルなのでブリッジに参加させたり、仮想 switch として扱えます:
# 例) ブリッジへ編入
sudo ip link add name br0 type bridge
sudo ip link set br0 up
sudo ip link set eip0 master br0
```

### 動作仕様（要点）

* 上位から `eipX` に流れてきた **Ethernet フレーム**を EtherIP ヘッダ（2 バイト, Version=3）でカプセル化し、**既存 IP スタック**（生 raw ソケット）で **宛先 IP** に送出します。
* 受信は **IP プロトコル番号 97 (EtherIP)** の IPv4/IPv6 ローカル配達パケットをプロトコルハンドラでフック。
  **送信元アドレスが当該デバイスに設定された `peer` と一致する場合のみ** EtherIP をデカプセル化し、eip デバイスが **Ethernet を受信**したかのように上に渡します。
* 送信用 MTU は、宛先が IPv4 の場合は `1500-20-2=1478`、IPv6 の場合は `1500-40-2=1458` を初期値として設定（`peer` を IPv4/IPv6 に変更すると自動調整）。必要に応じて `ip link set eip0 mtu ...` で調整してください。

---

## ソースコード

> すべて **GPL-2.0-only** で提供します。
> 文字コードは UTF-8 想定です。

### `eip/Makefile`（ツリー外ビルド用）

```make
# ツリー外（out-of-tree）ビルド用 Makefile
# 使い方: make && sudo insmod eip.ko

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m += eip.o
eip-y := eip_main.o eip_proto.o eip_sysctl.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

### `eip/Kbuild`

```make
obj-$(CONFIG_EIP) += eip.o
eip-y := eip_main.o eip_proto.o eip_sysctl.o
```

### `eip/Kconfig`

```none
# drivers/net/eip/Kconfig

config EIP
	tristate "EtherIP virtual device (eip)"
	depends on INET
	help
	  RFC 3378 EtherIP を用いた L2 over IP 仮想デバイス eip を提供します。
	  /proc/sys/net/eip/create に対する書き込みでデバイスを作成し、
	  /proc/sys/net/eip/<name>/{peer,mac} で宛先 IP と MAC を制御できます。
```

### `eip/eip.h`

```c
// SPDX-License-Identifier: GPL-2.0-only
//
// eip.h - EtherIP 仮想デバイス共通ヘッダ
//
// 本モジュールは RFC3378 EtherIP をカーネルモジュールとして提供し、
// eipX ネットデバイスを生成・制御します。

#ifndef _EIP_H_
#define _EIP_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sysctl.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include <net/inet_protocol.h>
#include <net/inet6_protocol.h>

#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP 97 /* IANA: EtherIP */
#endif

#define EIP_HDR_LEN     2
#define EIP_VERSION     3
#define EIP_HDR_VALUE   htons(0x3000) /* Version=3(上位4bit), 残り0 */

struct eip_priv;

/* グローバル一覧（RCU で参照） */
extern struct list_head eip_dev_list;
extern struct mutex eip_list_lock;

/* プライベート構造体: デバイス状態 */
struct eip_priv {
	struct net_device *dev;

	/* peer（宛先）: IPv4 or IPv6 */
	bool is_v6;
	union {
		__be32 v4;          /* IPv4: in_be32 */
		struct in6_addr v6; /* IPv6 */
	} peer;

	/* 自デバイス MAC（dev->dev_addr にも設定） */
	u8 mac[ETH_ALEN];

	/* 送信用カーネルソケット（AF_INET/AF_INET6 の RAW/IPPROTO_ETHERIP） */
	struct socket *ksock;
	int sock_family; /* AF_INET or AF_INET6, 0=未初期化 */

	/* 送信の軽量ロック（LLTX 想定） */
	spinlock_t tx_lock;

	/* 統計 */
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_dropped;
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_dropped;

	/* /proc/sys/net/eip/<name> 用 */
	struct ctl_table_header *sysctl_hdr;
	char sysctl_path[64];
	char peer_buf[64]; /* 読み書き用バッファ */
	char mac_buf[16];

	/* 一覧管理（RCU） */
	struct list_head list;
	struct rcu_head rcu;
};

/* 共通ユーティリティ */
static inline void eip_format_mac(char *out, const u8 mac[ETH_ALEN])
{
	/* 001122334455 形式（コロン無し） */
	snprintf(out, 13, "%02x%02x%02x%02x%02x%02x",
	        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 12 桁 HEX を MAC へ（コロン無し想定） */
static inline int eip_parse_mac(const char *s, u8 mac[ETH_ALEN])
{
	int i;
	if (strlen(s) != 12)
		return -EINVAL;
	for (i = 0; i < ETH_ALEN; i++) {
		unsigned int byte;
		if (sscanf(s + i*2, "%2x", &byte) != 1)
			return -EINVAL;
		mac[i] = (u8)byte;
	}
	return 0;
}

static inline void eip_mtu_by_family(struct net_device *dev, bool v6)
{
	/* EtherIP(2B) + IPv4(20B) or IPv6(40B) のヘッダ分を差し引く */
	int overhead = v6 ? (EIP_HDR_LEN + 40) : (EIP_HDR_LEN + 20);
	int mtu = ETH_DATA_LEN - overhead; /* 基本 1500 - overhead */
	if (mtu < 576 - overhead) /* 最低限の安全値（目安） */
		mtu = 576 - overhead;
	dev->mtu = mtu;
}

/* デバイス生成/破棄 API（sysctl から使用） */
int eip_create_dev(const char *name_opt, const char *peer_str, const char *mac_str, struct net_device **out);
void eip_destroy_all_devs(void);

/* 受信ハンドラ（IPv4/IPv6） */
int eip_ipv4_rcv(struct sk_buff *skb);
int eip_ipv6_rcv(struct sk_buff *skb);

/* sysctl 初期化/解放 */
int eip_sysctl_init(void);
void eip_sysctl_exit(void);
int eip_sysctl_register_dev(struct eip_priv *priv);
void eip_sysctl_unregister_dev(struct eip_priv *priv);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Example Contributor");
MODULE_DESCRIPTION("EtherIP (RFC3378) virtual device eip");

#endif /* _EIP_H_ */
```

### `eip/eip_main.c`

```c
// SPDX-License-Identifier: GPL-2.0-only
//
// eip_main.c - eip 仮想デバイス本体（生成・送信など）
//
// ここでは net_device 実装（ndo_*）とデバイス生成/破棄、
// 送信用 RAW ソケットの管理を行う。
// 受信（IP プロトコル 97 の着信処理）は eip_proto.c を参照。

#include "eip.h"

struct list_head eip_dev_list;
struct mutex eip_list_lock;

static int eip_open_sock(struct eip_priv *priv)
{
	int fam = priv->is_v6 ? AF_INET6 : AF_INET;
	struct socket *newsock;
	int err;

	if (priv->ksock && priv->sock_family == fam)
		return 0;

	if (priv->ksock) {
		sock_release(priv->ksock);
		priv->ksock = NULL;
		priv->sock_family = 0;
	}

	/* 送信用 RAW ソケット（IP ヘッダはカーネルで付与される） */
	err = sock_create_kern(&init_net, fam, SOCK_RAW, IPPROTO_ETHERIP, &newsock);
	if (err)
		return err;

	/* 非ブロッキングで使う（送信混雑で待たない） */
	newsock->sk->sk_allocation = GFP_ATOMIC;

	priv->ksock = newsock;
	priv->sock_family = fam;
	return 0;
}

/* peer 文字列を解析して priv->peer に格納（IPv4/IPv6 自動判定） */
static int eip_set_peer_from_str(struct eip_priv *priv, const char *s)
{
	/* in4_pton / in6_pton は <linux/inet.h> */
	__be32 v4;
	struct in6_addr v6;
	if (in4_pton(s, -1, (u8 *)&v4, -1, NULL)) {
		priv->is_v6 = false;
		priv->peer.v4 = v4;
		return 0;
	}
	if (in6_pton(s, -1, (u8 *)&v6, -1, NULL)) {
		priv->is_v6 = true;
		priv->peer.v6 = v6;
		return 0;
	}
	return -EINVAL;
}

static netdev_tx_t eip_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct eip_priv *priv = netdev_priv(dev);
	struct msghdr msg = {0};
	struct kvec iov[2];
	u16 hdr = ntohs(EIP_HDR_VALUE); /* 2 バイト固定ヘッダ: Version=3 */
	int ret;
	size_t len = skb->len + EIP_HDR_LEN;

	/* 宛先が未設定ならドロップ */
	if ((!priv->is_v6 && !priv->peer.v4) ||
	    (priv->is_v6 && ipv6_addr_any(&priv->peer.v6))) {
		priv->tx_dropped++;
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (eip_open_sock(priv)) {
		priv->tx_dropped++;
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	/* 宛先アドレス */
	if (priv->is_v6) {
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
			.sin6_port   = 0,
			.sin6_addr   = priv->peer.v6,
		};
		msg.msg_name    = &sin6;
		msg.msg_namelen = sizeof(sin6);
	} else {
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_port   = 0,
			.sin_addr.s_addr = priv->peer.v4,
		};
		msg.msg_name    = &sin;
		msg.msg_namelen = sizeof(sin);
	}

	/* EtherIP ヘッダ + Ethernet フレーム本体を iov で送る */
	iov[0].iov_base = &hdr;
	iov[0].iov_len  = EIP_HDR_LEN;

	/* 下層でコピーされるため、skb->data を直接参照 */
	iov[1].iov_base = skb->data;
	iov[1].iov_len  = skb->len;

	spin_lock(&priv->tx_lock);
	ret = kernel_sendmsg(priv->ksock, &msg, iov, 2, len);
	spin_unlock(&priv->tx_lock);

	if (ret >= 0) {
		priv->tx_packets++;
		priv->tx_bytes += skb->len;
	} else {
		priv->tx_dropped++;
	}
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int eip_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int eip_stop(struct net_device *dev)
{
	struct eip_priv *priv = netdev_priv(dev);
	netif_stop_queue(dev);
	if (priv->ksock) {
		sock_release(priv->ksock);
		priv->ksock = NULL;
		priv->sock_family = 0;
	}
	return 0;
}

static int eip_set_mac_address(struct net_device *dev, void *p)
{
	struct eip_priv *priv = netdev_priv(dev);
	struct sockaddr *addr = p;

	/* ここでは 6 バイト MAC をそのまま受ける（ユーザ空間の ip link set ...） */
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	ether_addr_copy(dev->dev_addr, addr->sa_data);
	ether_addr_copy(priv->mac, addr->sa_data);
	return 0;
}

static void eip_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *s)
{
	struct eip_priv *priv = netdev_priv(dev);
	/* 簡易的に u64 カウンタをコピー（競合は許容） */
	s->tx_packets = priv->tx_packets;
	s->tx_bytes   = priv->tx_bytes;
	s->tx_dropped = priv->tx_dropped;
	s->rx_packets = priv->rx_packets;
	s->rx_bytes   = priv->rx_bytes;
	s->rx_dropped = priv->rx_dropped;
}

static const struct net_device_ops eip_netdev_ops = {
	.ndo_open            = eip_open,
	.ndo_stop            = eip_stop,
	.ndo_start_xmit      = eip_start_xmit,
	.ndo_set_mac_address = eip_set_mac_address,
	.ndo_get_stats64     = eip_get_stats64,
};

static void eip_setup(struct net_device *dev)
{
	/* Ethernet デバイスとして初期化（L2 トンネルとして振る舞う） */
	ether_setup(dev);

	/* ARP は上位で実施可能だが、純粋な L2 トンネルなので NOARP にしても良い */
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;

	/* 軽量 TX キュー（自前ロック） */
	dev->features |= NETIF_F_LLTX;

	/* デフォルト MTU は IPv6 前提でやや保守的に */
	eip_mtu_by_family(dev, true);
}

int eip_create_dev(const char *name_opt, const char *peer_str, const char *mac_str, struct net_device **out)
{
	struct net_device *dev;
	struct eip_priv *priv;
	char name[IFNAMSIZ] = "eip%d";
	int err;

	/* 名前が指定されていれば使用、なければ eip%d */
	if (name_opt && name_opt[0]) {
		strscpy(name, name_opt, IFNAMSIZ);
	}

	dev = alloc_netdev(sizeof(*priv), name, NET_NAME_UNKNOWN, eip_setup);
	if (!dev)
		return -ENOMEM;

	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->ksock = NULL;
	priv->sock_family = 0;
	spin_lock_init(&priv->tx_lock);

	/* peer, mac を設定 */
	err = eip_set_peer_from_str(priv, peer_str);
	if (err)
		goto err_free;

	err = eip_parse_mac(mac_str, priv->mac);
	if (err)
		goto err_free;

	ether_addr_copy(dev->dev_addr, priv->mac);

	/* MTU は IP family に合わせる */
	eip_mtu_by_family(dev, priv->is_v6);

	/* 名前に %d が含まれていれば採番 */
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto err_free;
	}

	mutex_lock(&eip_list_lock);

	/* 登録 */
	err = register_netdev(dev);
	if (err) {
		mutex_unlock(&eip_list_lock);
		goto err_free;
	}

	/* /proc/sys/net/eip/<name> を登録 */
	err = eip_sysctl_register_dev(priv);
	if (err) {
		unregister_netdev(dev);
		mutex_unlock(&eip_list_lock);
		goto err_free;
	}

	/* 一覧へ（RCU） */
	list_add_rcu(&priv->list, &eip_dev_list);

	mutex_unlock(&eip_list_lock);

	if (out)
		*out = dev;
	return 0;

err_free:
	free_netdev(dev);
	return err;
}

static void __eip_destroy_dev(struct eip_priv *priv)
{
	/* sysctl を先に削除 */
	eip_sysctl_unregister_dev(priv);

	if (priv->ksock) {
		sock_release(priv->ksock);
		priv->ksock = NULL;
		priv->sock_family = 0;
	}
	unregister_netdev(priv->dev);
	free_netdev(priv->dev);
}

void eip_destroy_all_devs(void)
{
	struct eip_priv *priv, *tmp;

	mutex_lock(&eip_list_lock);

	list_for_each_entry_safe(priv, tmp, &eip_dev_list, list) {
		list_del_rcu(&priv->list);
		synchronize_rcu();
		__eip_destroy_dev(priv);
	}

	mutex_unlock(&eip_list_lock);
}

/* モジュール初期化/終了 */

static int __init eip_init(void)
{
	int ret;

	INIT_LIST_HEAD(&eip_dev_list);
	mutex_init(&eip_list_lock);

	/* sysctl ベース（/proc/sys/net/eip/create） */
	ret = eip_sysctl_init();
	if (ret)
		return ret;

	/* EtherIP 受信（IPv4/IPv6）を登録 */
	ret = inet_add_protocol(&(struct net_protocol){
		.handler   = eip_ipv4_rcv,
		.no_policy = 1,
		.netns_ok  = 1,
	}, IPPROTO_ETHERIP);
	if (ret) {
		eip_sysctl_exit();
		return ret;
	}

	ret = inet6_add_protocol(&(struct inet6_protocol){
		.handler    = eip_ipv6_rcv,
		.flags      = 0,
	}, IPPROTO_ETHERIP);
	if (ret) {
		inet_del_protocol(&(struct net_protocol){ .handler = eip_ipv4_rcv }, IPPROTO_ETHERIP);
		eip_sysctl_exit();
		return ret;
	}

	pr_info("eip: EtherIP virtual device loaded\n");
	return 0;
}

static void __exit eip_exit(void)
{
	/* 受信ハンドラ解除 */
	inet_del_protocol(&(struct net_protocol){ .handler = eip_ipv4_rcv }, IPPROTO_ETHERIP);
	inet6_del_protocol(&(struct inet6_protocol){ .handler = eip_ipv6_rcv }, IPPROTO_ETHERIP);

	/* すべての eip デバイスを破棄 */
	eip_destroy_all_devs();

	/* sysctl ベース解除 */
	eip_sysctl_exit();

	pr_info("eip: unloaded\n");
}

module_init(eip_init);
module_exit(eip_exit);
```

### `eip/eip_proto.c`

```c
// SPDX-License-Identifier: GPL-2.0-only
//
// eip_proto.c - EtherIP 受信（IPv4/IPv6 ローカル配達パス）
//
// IP 層でプロトコル番号 97 (EtherIP) にマッチしたパケットを受け取り、
// EtherIP ヘッダ(2B) を剥いで Ethernet フレームとして該当 eip デバイスへ注入する。
// 送信元がその eip デバイスに設定された peer と一致する場合のみ受け入れる。

#include "eip.h"

static struct eip_priv *eip_find_by_v4(__be32 saddr)
{
	struct eip_priv *p;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &eip_dev_list, list) {
		if (!p->is_v6 && p->peer.v4 == saddr) {
			rcu_read_unlock();
			return p;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static struct eip_priv *eip_find_by_v6(const struct in6_addr *saddr)
{
	struct eip_priv *p;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &eip_dev_list, list) {
		if (p->is_v6 && ipv6_addr_equal(&p->peer.v6, saddr)) {
			rcu_read_unlock();
			return p;
		}
	}
	rcu_read_unlock();
	return NULL;
}

/* EtherIP ヘッダ検査（Version=3, 残り0） */
static bool eip_check_hdr(const u8 *data, unsigned int len)
{
	u16 h;
	if (len < EIP_HDR_LEN)
		return false;
	h = (data[0] << 8) | data[1];
	/* 上位4bit が 3、下位12bit は 0 のはず */
	if (((h >> 12) & 0xF) != EIP_VERSION)
		return false;
	if ((h & 0x0FFF) != 0)
		return false;
	return true;
}

static int eip_rcv_common(struct sk_buff *skb, struct eip_priv *priv)
{
	/* EtherIP ヘッダ + Ethernet ヘッダがあるか */
	if (!pskb_may_pull(skb, EIP_HDR_LEN + ETH_HLEN))
		goto drop;

	/* EtherIP ヘッダを剝ぐ */
	if (!eip_check_hdr(skb->data, skb_headlen(skb)))
		goto drop;
	skb_pull(skb, EIP_HDR_LEN);

	/* この skb を eip デバイスから受信した体にして上位へ */
	skb->dev = priv->dev;
	skb->protocol = eth_type_trans(skb, priv->dev);
	skb->ip_summed = CHECKSUM_NONE;

	priv->rx_packets++;
	priv->rx_bytes += skb->len;

	netif_rx(skb);
	return 0;

drop:
	if (skb) {
		struct eip_priv *p = priv;
		if (p)
			p->rx_dropped++;
		kfree_skb(skb);
	}
	return 0;
}

int eip_ipv4_rcv(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct eip_priv *priv;

	if (!pskb_may_pull(skb, sizeof(struct iphdr) + EIP_HDR_LEN))
		goto drop;

	iph = ip_hdr(skb);
	/* ローカル配達済みのため、iph は有効 */

	priv = eip_find_by_v4(iph->saddr);
	if (!priv)
		goto drop;

	/* 以降は共通処理 */
	return eip_rcv_common(skb, priv);

drop:
	kfree_skb(skb);
	return 0;
}

int eip_ipv6_rcv(struct sk_buff *skb)
{
	struct ipv6hdr *ip6h;
	struct eip_priv *priv;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + EIP_HDR_LEN))
		goto drop;

	ip6h = ipv6_hdr(skb);

	priv = eip_find_by_v6(&ip6h->saddr);
	if (!priv)
		goto drop;

	return eip_rcv_common(skb, priv);

drop:
	kfree_skb(skb);
	return 0;
}
```

### `eip/eip_sysctl.c`

```c
// SPDX-License-Identifier: GPL-2.0-only
//
// eip_sysctl.c - /proc/sys/net/eip/* の制御
//
// - /proc/sys/net/eip/create への書き込みでデバイス作成
//   書式: "add dst=<IPv4|IPv6> mac=<12hex> [name=<eipX>]"
//
// - /proc/sys/net/eip/<name>/peer, mac の読み書き
//   peer: ASCII の IP 文字列（例 "198.51.100.1", "2001:db8::1"）
//   mac : 12 桁 HEX（例 "001122334455"）
//   ※ 書き込みは root（CAP_NET_ADMIN）のみ、読み取りは誰でも可能

#include "eip.h"

static struct ctl_table_header *eip_sysctl_root;
static char create_buf[256];

static int need_cap_net_admin(void)
{
	return !capable(CAP_NET_ADMIN);
}

/* "key=value" の value を out にコピー（存在しなければ NULL） */
static const char *kv_find(const char *buf, const char *key, char *out, size_t outlen)
{
	const char *p = strstr(buf, key);
	const char *eq, *sp;
	size_t n;

	if (!p)
		return NULL;
	eq = strchr(p, '=');
	if (!eq)
		return NULL;
	eq++; /* '=' の次 */

	/* 値はスペースか行末まで */
	sp = strpbrk(eq, " \t\r\n");
	if (!sp)
		sp = eq + strlen(eq);

	n = min((size_t)(sp - eq), outlen - 1);
	memcpy(out, eq, n);
	out[n] = '\0';
	return out;
}

static int eip_sysctl_create(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	/* 読み取り時はヘルプを返す */
	if (!write) {
		static const char help[] =
"Usage: echo \"add dst=<IPv4|IPv6> mac=<12hex> [name=<eipX>]\" > /proc/sys/net/eip/create\n";
		return proc_dostring(&(struct ctl_table){
			.data     = (char *)help,
			.maxlen   = sizeof(help),
			.mode     = 0444,
			.proc_handler = proc_dostring,
		}, 0, buffer, lenp, ppos);
	}

	if (need_cap_net_admin())
		return -EPERM;

	/* ユーザ文字列を取り込む */
	ret = proc_dostring(&(struct ctl_table){
		.data     = create_buf,
		.maxlen   = sizeof(create_buf),
		.mode     = 0644,
		.proc_handler = proc_dostring,
	}, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	/* 解析 */
	{
		char dst[64] = {0}, mac[16] = {0}, name[IFNAMSIZ] = {0};
		struct net_device *dev = NULL;

		if (!kv_find(create_buf, "dst", dst, sizeof(dst)))
			return -EINVAL;
		if (!kv_find(create_buf, "mac", mac, sizeof(mac)))
			return -EINVAL;
		/* name は任意 */
		if (!kv_find(create_buf, "name", name, sizeof(name)))
			name[0] = '\0';

		ret = eip_create_dev(name[0] ? name : NULL, dst, mac, &dev);
		if (ret)
			return ret;
	}
	return 0;
}

/* --- per-device sysctl: peer, mac --- */

static int eip_sysctl_peer(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct eip_priv *priv = table->extra1;
	int ret;

	if (!write) {
		/* 現在値を文字列化して返す */
		if (priv->is_v6) {
			snprintf(priv->peer_buf, sizeof(priv->peer_buf),
			         "%pI6c", &priv->peer.v6);
		} else {
			snprintf(priv->peer_buf, sizeof(priv->peer_buf),
			         "%pI4", &priv->peer.v4);
		}
		return proc_dostring(&(struct ctl_table){
			.data     = priv->peer_buf,
			.maxlen   = sizeof(priv->peer_buf),
			.mode     = 0444,
			.proc_handler = proc_dostring,
		}, 0, buffer, lenp, ppos);
	}

	if (need_cap_net_admin())
		return -EPERM;

	/* 入力取り込み */
	ret = proc_dostring(&(struct ctl_table){
		.data     = priv->peer_buf,
		.maxlen   = sizeof(priv->peer_buf),
		.mode     = 0644,
		.proc_handler = proc_dostring,
	}, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	/* 解析して反映（ソケットと MTU も更新） */
	ret = ({ int __r = 0;
		struct eip_priv *__p = priv;
		__r = ({ int ___r = 0;
			___r = ({
				/* peer のパース */
				eip_set_peer_from_str(__p, __p->peer_buf);
			});
			___r;
		});
		if (!__r) {
			/* family に応じて MTU 更新 */
			eip_mtu_by_family(__p->dev, __p->is_v6);
			/* 送信用ソケットも作り直す */
			if (__p->ksock) {
				sock_release(__p->ksock);
				__p->ksock = NULL;
				__p->sock_family = 0;
			}
		}
		__r;
	});
	return ret;
}

static int eip_sysctl_mac(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct eip_priv *priv = table->extra1;
	int ret;

	if (!write) {
		eip_format_mac(priv->mac_buf, priv->mac);
		return proc_dostring(&(struct ctl_table){
			.data     = priv->mac_buf,
			.maxlen   = sizeof(priv->mac_buf),
			.mode     = 0444,
			.proc_handler = proc_dostring,
		}, 0, buffer, lenp, ppos);
	}

	if (need_cap_net_admin())
		return -EPERM;

	ret = proc_dostring(&(struct ctl_table){
		.data     = priv->mac_buf,
		.maxlen   = sizeof(priv->mac_buf),
		.mode     = 0644,
		.proc_handler = proc_dostring,
	}, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	ret = eip_parse_mac(priv->mac_buf, priv->mac);
	if (ret)
		return ret;

	ether_addr_copy(priv->dev->dev_addr, priv->mac);
	return 0;
}

/* ベース: /proc/sys/net/eip/ */
int eip_sysctl_init(void)
{
	static struct ctl_table eip_root_tbl[] = {
		{
			.procname	= "create",
			.mode		= 0644, /* 読み:誰でも, 書き:root のみ (cap チェック有) */
			.proc_handler	= eip_sysctl_create,
		},
		{ }
	};

	eip_sysctl_root = register_net_sysctl(&init_net, "net/eip", eip_root_tbl);
	if (!eip_sysctl_root)
		return -ENOMEM;
	return 0;
}

void eip_sysctl_exit(void)
{
	if (eip_sysctl_root) {
		unregister_net_sysctl_table(eip_sysctl_root);
		eip_sysctl_root = NULL;
	}
}

/* /proc/sys/net/eip/<name>/ の登録 */
int eip_sysctl_register_dev(struct eip_priv *priv)
{
	struct ctl_table *tbl;

	snprintf(priv->sysctl_path, sizeof(priv->sysctl_path),
	         "net/eip/%s", priv->dev->name);

	tbl = kzalloc(sizeof(struct ctl_table) * 3, GFP_KERNEL);
	if (!tbl)
		return -ENOMEM;

	/* peer */
	tbl[0].procname     = "peer";
	tbl[0].mode         = 0644;
	tbl[0].proc_handler = eip_sysctl_peer;
	tbl[0].extra1       = priv; /* ハンドラ内で参照 */

	/* mac */
	tbl[1].procname     = "mac";
	tbl[1].mode         = 0644;
	tbl[1].proc_handler = eip_sysctl_mac;
	tbl[1].extra1       = priv;

	/* 終端は {0} */

	priv->sysctl_hdr = register_net_sysctl(&init_net, priv->sysctl_path, tbl);
	if (!priv->sysctl_hdr) {
		kfree(tbl);
		return -ENOMEM;
	}

	/* register_net_sysctl は ctl_table の実体を保持しないため、tbl は解放せず
	 * priv->sysctl_hdr の破棄時に一緒に解放する必要がある……のが旧 API でしたが、
	 * 6.x では内部で table を参照するため、このまま tbl を保持しておきます。
	 * → シンプルに hdr の private を使えないので、ここでは hdr 解放時に tbl も解放。
	 * （unregister 時に kfree を行う）
	 */
	priv->sysctl_hdr->ctl_table_arg = tbl; /* 注意: 内部構造依存が嫌なら priv に保持して解放でも可 */
	return 0;
}

void eip_sysctl_unregister_dev(struct eip_priv *priv)
{
	if (priv->sysctl_hdr) {
		struct ctl_table *tbl = priv->sysctl_hdr->ctl_table_arg;
		unregister_net_sysctl_table(priv->sysctl_hdr);
		priv->sysctl_hdr = NULL;
		kfree(tbl);
	}
}
```

> ※ `ctl_table_arg` の扱いはカーネルにより内部実装差があるため、気になる場合は `priv` に `struct ctl_table *dev_sysctl_tbl;` を持たせて別管理し、`register_net_sysctl` 成功後も **解放せず保持**、`unregister` 時に `kfree()` する形にしてください。

---

## 実装上のポイント（コメント抜粋）

* **EtherIP ヘッダ**は 2 バイト固定、上位 4bit が Version=3、残り 12bit は 0。`htons(0x3000)` を使用。
* 送信は **カーネル RAW ソケット**（`SOCK_RAW` / `IPPROTO_ETHERIP`）で実施。IP ヘッダ付与とルーティングは既存スタックに任せます。
* 受信は IPv4/IPv6 で **プロトコルハンドラ**（`inet_add_protocol` / `inet6_add_protocol`）を登録し、**ローカル配達された EtherIP**の decap を行います。
* `/proc/sys/net/eip/create` に `"add dst=... mac=... [name=...]"` を書き込むとデバイス作成。
  per-device の `/proc/sys/net/eip/<name>/{peer,mac}` は **root のみ書込可**（CAP\_NET\_ADMIN チェック）、**誰でも読取可**（`0444/0644` と実効権限チェック）。
* MTU は family に応じて `1500 - (IPヘッダ + 2)` に自動調整（`peer` 変更時に再計算）。
* 統計は簡易カウンタ（`ndo_get_stats64`）で参照可能。

---

## テストのヒント

```bash
# モジュール挿入
sudo insmod eip.ko

# eip0 作成 (IPv4)
echo "add dst=192.0.2.10 mac=001122334455 name=eip0" | sudo tee /proc/sys/net/eip/create
ip link show eip0
sudo ip link set eip0 up

# 宛先/自 MAC の確認
cat /proc/sys/net/eip/eip0/peer
cat /proc/sys/net/eip/eip0/mac

# IPv6 に変更
echo "2001:db8::1" | sudo tee /proc/sys/net/eip/eip0/peer
cat /proc/sys/net/eip/eip0/peer

# ブリッジに参加（例）
sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip link set eip0 master br0

# 統計
ip -s link show eip0

# アンロード
sudo rmmod eip
```

---

## 補足・拡張アイデア

* **netns 対応**：`register_net_sysctl` の `&init_net` を `dev_net(priv->dev)` に合わせ、受信側の検索も netns を考慮して分離するとより良いです。
* **セキュリティ**：送信元チェックは厳格（現在は完全一致）。必要なら SPI/鍵管理や更なるフィルタを追加。
* **オフロード**：CSUM/OFFLOAD まわりは用途に応じて最適化可能。
* **削除インターフェイス**：`/proc/sys/net/eip/eipX/delete` などで削除可能にするのも一案です。

---

必要に応じて、このまま ZIP 化したり、社内コード規約に合わせた整形・命名の調整版も用意できます。
