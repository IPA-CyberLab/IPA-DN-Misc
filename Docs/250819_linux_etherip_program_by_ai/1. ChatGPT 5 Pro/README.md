以下は、Linux カーネル 6.8 系でビルド・動作する **EtherIP (RFC 3378)** の仮想ネットワークデバイスドライバ（モジュール）実装一式です。
要件に沿い、

* インターフェイス名は `eip0`, `eip1`, …
* `/proc/sys/net/eip/` 配下の **root 書込 / 全員読取** な sysctl 風コントロールファイルで **作成** と **設定**（宛先 IP(v4/v6) と MAC アドレス）
* L2 フレーム送出時は EtherIP (IP プロトコル番号 97) でカプセル化し、Linux の IP スタックを用いて転送
* EtherIP 受信時は、**宛先設定 (peer) と一致する送信元アドレスからのパケットのみ**をデカプセル化して `eipX` に受信させる

を実装しています。
**各ファイルとも日本語の詳細コメント**を付けています。

---

## ファイル構成

```
eip/
├── Kconfig
├── Makefile
├── README.md
├── eip.h
└── eip_main.c
```

---

## `eip.h`

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * eip.h - EtherIP 仮想デバイス ドライバ（ヘッダ）
 *
 * 本モジュールは RFC 3378 (EtherIP) を用いて Ethernet フレームを
 * IP パケット (Protocol 97) にカプセル化して転送/受信する。
 */

#ifndef _LINUX_EIP_H_
#define _LINUX_EIP_H_

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/in6.h>

#ifndef IPPROTO_ETHERIP
/* EtherIP の IP プロトコル番号（IPv4/IPv6 共通） */
#define IPPROTO_ETHERIP 97
#endif

#define EIP_DRV_NAME     "eip"
#define EIP_DRV_VERSION  "0.2"

/* EtherIP ヘッダは 16bit。上位4bit=Version(3)、下位12bit=予約(0)。BE で 0x3000。*/
#define EIP_HDR_BE16     0x3000

/* peer 表示用の文字列バッファ長 */
#define EIP_PEER_BUFSZ   64
/* mac 表示用の文字列バッファ長（"001122334455" または "00:11:22:33:44:55" 等） */
#define EIP_MAC_BUFSZ    32

/* peer のアドレス種別 */
enum eip_af {
	EIP_AF_NONE = 0,
	EIP_AF_INET = AF_INET,
	EIP_AF_INET6 = AF_INET6,
};

/* net namespace 毎の管理情報 */
struct eip_net {
	struct list_head devices;              /* 当該 netns 内の eip デバイス一覧 */
	struct ctl_table_header *sysctl_hdr;   /* /proc/sys/net/eip/ のルート */
	char last_created[IFNAMSIZ];           /* 直近に作成されたIF名の記憶 */
	char create_buf[EIP_PEER_BUFSZ];       /* create ファイルへの一時バッファ */
};

struct eip_priv {
	struct net_device *dev;        /* 自身の net_device */
	struct net *net;               /* 所属 netns */

	/* 設定パラメータ */
	enum eip_af af;                /* 宛先アドレスのファミリ */
	union {
		__be32 v4;
		struct in6_addr v6;
	} peer;                        /* 宛先 IP (v4/v6) */
	u8 mac[ETH_ALEN];              /* デバイスの MAC（コントロールで変更可） */

	/* 送信用ソケット（カーネル空間の SOCK_RAW） */
	struct socket *sock4;          /* AF_INET  用 (IPPROTO_ETHERIP) */
	struct socket *sock6;          /* AF_INET6 用 (IPPROTO_ETHERIP) */
	spinlock_t sock_lock;          /* sock 作成/破棄の排他 */

	/* /proc/sys/net/eip/eipX/ 用の sysctl ハンドル */
	struct ctl_table_header *sysctl_hdr;

	/* sysctl の文字列表現バッファ（読み書きの橋渡しに使う） */
	char peer_buf[EIP_PEER_BUFSZ];
	char mac_buf[EIP_MAC_BUFSZ];

	/* 統計（簡易） */
	u64 tx_pkts, tx_bytes, tx_dropped;
	u64 rx_pkts, rx_bytes, rx_dropped;

	/* netns 内リンク */
	struct list_head list_node;
};

extern unsigned int eip_net_id;

/* RX パスから使う検索関数 */
struct net_device *eip_lookup_by_v4(struct net *net, __be32 saddr);
struct net_device *eip_lookup_by_v6(struct net *net, const struct in6_addr *saddr);

/* sysctl の初期化/解放（netns 毎） */
int  eip_sysctl_net_init(struct net *net);
void eip_sysctl_net_exit(struct net *net);

/* デバイス作成（/proc/sys/net/eip/create から呼び出される） */
int eip_create_dev_in_netns(struct net *net, char *created_name, size_t created_len);

#endif /* _LINUX_EIP_H_ */
```

---

## `eip_main.c`

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * eip_main.c - EtherIP 仮想デバイス ドライバ本体
 *
 * 重要ポイント:
 *  - デバイス名は eip%d （例: eip0, eip1 ...）
 *  - /proc/sys/net/eip/ 以下のコントロールファイルで作成・設定
 *     * create : 書き込みで新規 eipX を作成（root のみ書込可・誰でも読取可）
 *     * eipX/peer : 宛先 IP(v4/v6) を ASCII で設定/表示
 *     * eipX/mac  : デバイス MAC を 12 桁 HEX (or コロン区切り) で設定/表示
 *  - 送信: L2 フレームを EtherIP (IP proto 97) でカプセル化し raw ソケット送信
 *  - 受信: IP スタックから EtherIP (97) をフック。ヘッダ 0x3000 を確認し、
 *          送信元アドレスが peer と一致するデバイスに L2 フレームとして配送
 *
 * ★本実装は最小限の参考用コードです。実運用ではセキュリティ/MTU/エラー処理など
 *   を十分検討してください。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/sysctl.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/inet.h>        /* in4_pton, in6_pton */
#include <net/sock.h>
#include <net/protocol.h>      /* inet_add_protocol, inet6_add_protocol */
#include "eip.h"

MODULE_AUTHOR("Example Author");
MODULE_DESCRIPTION("EtherIP (RFC3378) virtual device (eipX)");
MODULE_LICENSE("GPL");
MODULE_VERSION(EIP_DRV_VERSION);

/* -------- netns 管理 --------------------------------------------------- */

unsigned int eip_net_id; /* net_generic 用の ID を保持 */

static int eip_pernet_init(struct net *net)
{
	struct eip_net *en = net_generic(net, eip_net_id);
	INIT_LIST_HEAD(&en->devices);
	memset(en->last_created, 0, sizeof(en->last_created));
	memset(en->create_buf, 0, sizeof(en->create_buf));
	return eip_sysctl_net_init(net);
}

static void eip_pernet_exit(struct net *net)
{
	eip_sysctl_net_exit(net);
}

static struct pernet_operations eip_pernet_ops = {
	.init = eip_pernet_init,
	.exit = eip_pernet_exit,
	.id   = &eip_net_id,
	.size = sizeof(struct eip_net),
};

/* -------- ユーティリティ ------------------------------------------------ */

/* 12桁HEX または コロン区切り "aa:bb:cc:dd:ee:ff" を受け取り MAC に変換 */
static int eip_parse_mac(const char *s, u8 *out)
{
	int i, n = 0;
	char buf[EIP_MAC_BUFSZ];
	const char *p = s;

	/* 改行・末尾空白を除去しつつコピー */
	for (i = 0; i < (int)sizeof(buf) - 1 && *p; ++i, ++p) {
		if (*p == '\n' || *p == '\r') break;
		buf[i] = *p;
	}
	buf[i] = '\0';

	/* コロン有り/無しの双方を許容する（仕様上は12桁HEX）。*/
	if (strchr(buf, ':')) {
		unsigned int b[ETH_ALEN];
		if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
		           &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
			return -EINVAL;
		for (i = 0; i < ETH_ALEN; i++)
			out[i] = (u8)b[i];
		return 0;
	}

	/* コロン無し 12 桁 HEX */
	if (strlen(buf) != 12)
		return -EINVAL;
	for (i = 0; i < ETH_ALEN; i++) {
		char tmp[3] = { buf[n++], buf[n++], 0 };
		if (!isxdigit(tmp[0]) || !isxdigit(tmp[1]))
			return -EINVAL;
		out[i] = (u8)simple_strtoul(tmp, NULL, 16);
	}
	return 0;
}

static void eip_format_mac(const u8 *mac, char *out, size_t outlen)
{
	/* 仕様は 12 文字 HEX 表記を要求、ここではそれに合わせて出力する */
	snprintf(out, outlen, "%02x%02x%02x%02x%02x%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* -------- sysctl (/proc/sys/net/eip/*) --------------------------------- */

/*
 * /proc/sys/net/eip/create
 *   - 書き込み: 新規 eipX を作成（書式は任意。何か書けば作成）
 *   - 読み出し: 直近に作成された IF 名（例: "eip0"）
 *
 * パーミッションは 0644（root 書込、誰でも読取）
 */

static int eip_sysctl_create(struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = table->extra1; /* netns を extra1 で受け渡し */
	struct eip_net *en = net_generic(net, eip_net_id);
	int ret;

	/* table->data は en->create_buf に設定済み */
	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (write) {
		/* 実際の文字列内容は特に見ない。書込をトリガとして作成。 */
		char name[IFNAMSIZ] = {0};
		int rc = eip_create_dev_in_netns(net, name, sizeof(name));
		if (rc)
			return rc;
		strscpy(en->last_created, name, sizeof(en->last_created));
		/* 読み出し時に直近作成名が返るようバッファに反映 */
		strscpy(en->create_buf, en->last_created, sizeof(en->create_buf));
	} else {
		/* 読み出し: last_created を返す（空なら空文字） */
		strscpy(en->create_buf, en->last_created, sizeof(en->create_buf));
	}
	return 0;
}

/* eipX/peer: 宛先 IP アドレス (IPv4/IPv6) の設定/表示 */
static int eip_sysctl_peer(struct ctl_table *table, int write,
			   void *buffer, size_t *lenp, loff_t *ppos)
{
	struct eip_priv *priv = table->data; /* data に eip_priv を渡してある */
	int ret;

	/* 読み出し時は現設定を文字列化してから proc_dostring に渡す */
	if (!write) {
		if (priv->af == EIP_AF_INET)
			snprintf(priv->peer_buf, sizeof(priv->peer_buf), "%pI4\n", &priv->peer.v4);
		else if (priv->af == EIP_AF_INET6)
			snprintf(priv->peer_buf, sizeof(priv->peer_buf), "%pI6c\n", &priv->peer.v6);
		else
			snprintf(priv->peer_buf, sizeof(priv->peer_buf), "none\n");
	}

	/* table->data を一時的に peer_buf に差し替え、通常の string として処理させる */
	{
		char *saved = table->data;
		size_t saved_len = table->maxlen;
		table->data  = priv->peer_buf;
		table->maxlen = sizeof(priv->peer_buf);
		ret = proc_dostring(table, write, buffer, lenp, ppos);
		table->data  = saved;
		table->maxlen = saved_len;
		if (ret)
			return ret;
	}

	if (write) {
		/* 入力値（改行除去済み）を解析して設定反映 */
		char *s = strim(priv->peer_buf);
		enum eip_af new_af = EIP_AF_NONE;
		union { __be32 v4; struct in6_addr v6; } new_peer = {};

		if (!*s || !strcmp(s, "none")) {
			new_af = EIP_AF_NONE;
		} else if (in4_pton(s, -1, (u8 *)&new_peer.v4, -1, NULL)) {
			new_af = EIP_AF_INET;
		} else if (in6_pton(s, -1, (u8 *)&new_peer.v6, -1, NULL)) {
			new_af = EIP_AF_INET6;
		} else {
			return -EINVAL;
		}

		rtnl_lock();
		/* 設定更新（sock の準備は送信時に lazy に行う） */
		priv->af = new_af;
		if (new_af == EIP_AF_INET)
			priv->peer.v4 = new_peer.v4;
		else if (new_af == EIP_AF_INET6)
			priv->peer.v6 = new_peer.v6;
		rtnl_unlock();
	}

	return 0;
}

/* eipX/mac: 12 桁 HEX（またはコロン区切り）で MAC 設定/表示 */
static int eip_sysctl_mac(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct eip_priv *priv = table->data;
	int ret;

	if (!write)
		eip_format_mac(priv->dev->dev_addr, priv->mac_buf, sizeof(priv->mac_buf));

	/* 一時的に mac_buf を string として proc_dostring に渡す */
	{
		char *saved = table->data;
		size_t saved_len = table->maxlen;
		table->data  = priv->mac_buf;
		table->maxlen = sizeof(priv->mac_buf);
		ret = proc_dostring(table, write, buffer, lenp, ppos);
		table->data  = saved;
		table->maxlen = saved_len;
		if (ret)
			return ret;
	}

	if (write) {
		u8 mac[ETH_ALEN];
		int rc = eip_parse_mac(priv->mac_buf, mac);
		if (rc)
			return rc;
		rtnl_lock();
		eth_hw_addr_set(priv->dev, mac);
		memcpy(priv->mac, mac, ETH_ALEN);
		rtnl_unlock();
	}
	return 0;
}

/* netns 直下の sysctl テーブル */
static struct ctl_table eip_sysctl_root_template[] = {
	{
		.procname     = "create",
		.maxlen       = EIP_PEER_BUFSZ,
		.mode         = 0644, /* 誰でも読取・root のみ書込 */
		.proc_handler = eip_sysctl_create,
		/* extra1 に netns を渡す。data は後で set。*/
	},
	{ } /* 終端 */
};

int eip_sysctl_net_init(struct net *net)
{
	struct eip_net *en = net_generic(net, eip_net_id);
	struct ctl_table *root;
	char path[] = "net/eip";

	/* root テーブルを複製して netns ごとに確保 */
	root = kcalloc(ARRAY_SIZE(eip_sysctl_root_template),
	               sizeof(struct ctl_table), GFP_KERNEL);
	if (!root)
		return -ENOMEM;

	memcpy(root, eip_sysctl_root_template, sizeof(eip_sysctl_root_template));
	/* "create" の data/extra1 を設定 */
	root[0].data   = en->create_buf;
	root[0].extra1 = net; /* ハンドラに netns を渡す */

	en->sysctl_hdr = register_net_sysctl(net, path, root);
	if (!en->sysctl_hdr) {
		kfree(root);
		return -ENOMEM;
	}
	/* register_* は中で table を所有し、unregister 時に解放される */
	return 0;
}

void eip_sysctl_net_exit(struct net *net)
{
	struct eip_net *en = net_generic(net, eip_net_id);
	if (en->sysctl_hdr) {
		unregister_net_sysctl_table(en->sysctl_hdr);
		en->sysctl_hdr = NULL;
	}
}

/* 指定デバイス用の /proc/sys/net/eip/eipX/ を登録 */
static int eip_register_dev_sysctl(struct eip_priv *priv)
{
	struct ctl_table *tbl;
	char path[64];

	snprintf(path, sizeof(path), "net/%s/%s", EIP_DRV_NAME, priv->dev->name);

	/* peer, mac の2エントリ */
	tbl = kcalloc(3, sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return -ENOMEM;

	tbl[0].procname     = "peer";
	tbl[0].maxlen       = EIP_PEER_BUFSZ;
	tbl[0].mode         = 0644;
	tbl[0].proc_handler = eip_sysctl_peer;
	tbl[0].data         = priv; /* ハンドラへ渡す */

	tbl[1].procname     = "mac";
	tbl[1].maxlen       = EIP_MAC_BUFSZ;
	tbl[1].mode         = 0644;
	tbl[1].proc_handler = eip_sysctl_mac;
	tbl[1].data         = priv;

	priv->sysctl_hdr = register_net_sysctl(priv->net, path, tbl);
	if (!priv->sysctl_hdr) {
		kfree(tbl);
		return -ENOMEM;
	}
	return 0;
}

/* -------- net_device 実装 ---------------------------------------------- */

static netdev_tx_t eip_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct eip_priv *priv = netdev_priv(dev);
	struct msghdr msg = {0};
	struct kvec iov[2];
	int sent, total;
	__be16 eh = cpu_to_be16(EIP_HDR_BE16);
	int err = 0;

	/* 送信先 (peer) が未設定なら破棄 */
	if (READ_ONCE(priv->af) == EIP_AF_NONE) {
drop:
		priv->tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* SKB を線形化（kvec で一括送信するため） */
	if (skb_linearize(skb))
		goto drop;

	/* EtherIP ヘッダ + Ethernet フレーム本体 を 2セグメントで送る */
	iov[0].iov_base = &eh;
	iov[0].iov_len  = sizeof(eh);
	iov[1].iov_base = skb->data;
	iov[1].iov_len  = skb->len;

	spin_lock_bh(&priv->sock_lock);

	if (priv->af == EIP_AF_INET) {
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = priv->peer.v4,
		};
		if (!priv->sock4) {
			/* AF_INET/RAW/ETHERIP の送信用ソケットを生成 */
			err = sock_create_kern(priv->net, AF_INET, SOCK_RAW,
			                       IPPROTO_ETHERIP, &priv->sock4);
			if (err) {
				priv->sock4 = NULL;
				spin_unlock_bh(&priv->sock_lock);
				goto drop;
			}
		}
		msg.msg_name    = &sin;
		msg.msg_namelen = sizeof(sin);
		total = iov[0].iov_len + iov[1].iov_len;
		sent = kernel_sendmsg(priv->sock4, &msg, iov, 2, total);
	} else { /* IPv6 */
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
			.sin6_addr   = priv->peer.v6,
		};
		if (!priv->sock6) {
			err = sock_create_kern(priv->net, AF_INET6, SOCK_RAW,
			                       IPPROTO_ETHERIP, &priv->sock6);
			if (err) {
				priv->sock6 = NULL;
				spin_unlock_bh(&priv->sock_lock);
				goto drop;
			}
		}
		msg.msg_name    = &sin6;
		msg.msg_namelen = sizeof(sin6);
		total = iov[0].iov_len + iov[1].iov_len;
		sent = kernel_sendmsg(priv->sock6, &msg, iov, 2, total);
	}

	spin_unlock_bh(&priv->sock_lock);

	if (sent < 0) {
		priv->tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	priv->tx_pkts++;
	priv->tx_bytes += skb->len;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int eip_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int eip_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

/* 64bit 統計を返す */
static void eip_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *s)
{
	struct eip_priv *p = netdev_priv(dev);
	s->tx_packets = p->tx_pkts;
	s->tx_bytes   = p->tx_bytes;
	s->tx_dropped = p->tx_dropped;
	s->rx_packets = p->rx_pkts;
	s->rx_bytes   = p->rx_bytes;
	s->rx_dropped = p->rx_dropped;
}

/* MAC を ip link 等から変更できるようにもしておく（sysctl と同等） */
static int eip_set_mac_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	eth_hw_addr_set(dev, addr->sa_data);
	memcpy(((struct eip_priv *)netdev_priv(dev))->mac, addr->sa_data, ETH_ALEN);
	return 0;
}

static const struct net_device_ops eip_netdev_ops = {
	.ndo_open         = eip_open,
	.ndo_stop         = eip_stop,
	.ndo_start_xmit   = eip_start_xmit,
	.ndo_set_mac_address = eip_set_mac_address,
	.ndo_get_stats64  = eip_get_stats64,
};

static void eip_setup(struct net_device *dev)
{
	struct eip_priv *priv = netdev_priv(dev);

	/* ベースを Ethernet デバイス相当に設定 */
	ether_setup(dev);
	dev->netdev_ops = &eip_netdev_ops;

	/* EtherIP のオーバーヘッドは 2B (+ 外側IPヘッダ)。
	 * MTU は簡易実装としてデフォルト 1500 のまま（外側でフラグメントされ得る）。
	 * 実運用では path MTU に応じた調整を検討すること。
	 */

	dev->tx_queue_len = 1000;
	dev->flags |= IFF_NOARP;          /* 仮想デバイスなので ARP 解決不要 */
	dev->features |= NETIF_F_LLTX;    /* lockless TX */

	/* 初期 MAC はランダム。のちに sysctl で上書き可能。*/
	eth_hw_addr_random(dev);

	/* プライベート初期化 */
	memset(priv, 0, sizeof(*priv));
	priv->dev = dev;
	priv->net = dev_net(dev);
	memcpy(priv->mac, dev->dev_addr, ETH_ALEN);
	spin_lock_init(&priv->sock_lock);
	priv->af = EIP_AF_NONE;
}

/* デバイス生成（create ファイルから呼ばれる） */
int eip_create_dev_in_netns(struct net *net, char *created_name, size_t created_len)
{
	struct net_device *dev;
	struct eip_priv *priv;
	struct eip_net *en = net_generic(net, eip_net_id);
	int rc;

	dev = alloc_netdev(sizeof(struct eip_priv), EIP_DRV_NAME "%d",
	                   NET_NAME_ENUM, eip_setup);
	if (!dev)
		return -ENOMEM;

	dev_net_set(dev, net);

	rc = register_netdev(dev);
	if (rc) {
		free_netdev(dev);
		return rc;
	}

	priv = netdev_priv(dev);

	/* netns のデバイスリストに登録（RCU 可視化） */
	rtnl_lock();
	list_add_rcu(&priv->list_node, &en->devices);
	rtnl_unlock();

	/* /proc/sys/net/eip/eipX/ の登録 */
	rc = eip_register_dev_sysctl(priv);
	if (rc) {
		/* sysctl 登録失敗時はデバイスを撤収 */
		rtnl_lock();
		list_del_rcu(&priv->list_node);
		rtnl_unlock();
		unregister_netdev(dev);
		free_netdev(dev);
		return rc;
	}

	strscpy(created_name, dev->name, created_len);
	return 0;
}

/* -------- EtherIP 受信 (IPv4/IPv6) ------------------------------------ */

/*
 * IP スタックから Protocol=97 (EtherIP) を受け取るフック。
 *  - 16bit EtherIP ヘッダ (0x3000) を確認
 *  - 送信元 IP が一致する eipX を探索
 *  - デカプセル化して eipX が受信したように上位へ渡す
 *
 * 注意: 本ハンドラはローカル配送 (ip_local_deliver) のフェーズで呼び出される。
 *       skb->data は外側 IP ヘッダ直後（= EtherIP ヘッダ先頭）を指す。
 */

static struct net_device *eip_lookup_rcu_v4(struct net *net, __be32 saddr)
{
	struct eip_net *en = net_generic(net, eip_net_id);
	struct eip_priv *p;

	list_for_each_entry_rcu(p, &en->devices, list_node) {
		if (READ_ONCE(p->af) == EIP_AF_INET &&
		    p->peer.v4 == saddr)
			return p->dev;
	}
	return NULL;
}

static struct net_device *eip_lookup_rcu_v6(struct net *net, const struct in6_addr *saddr)
{
	struct eip_net *en = net_generic(net, eip_net_id);
	struct eip_priv *p;

	list_for_each_entry_rcu(p, &en->devices, list_node) {
		if (READ_ONCE(p->af) == EIP_AF_INET6 &&
		    ipv6_addr_equal(&p->peer.v6, saddr))
			return p->dev;
	}
	return NULL;
}

/* 公開（ヘッダに宣言） */
struct net_device *eip_lookup_by_v4(struct net *net, __be32 saddr)
{
	return eip_lookup_rcu_v4(net, saddr);
}
struct net_device *eip_lookup_by_v6(struct net *net, const struct in6_addr *saddr)
{
	return eip_lookup_rcu_v6(net, saddr);
}

static int eip_ipv4_rcv(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct net *net = dev_net(skb->dev);
	struct net_device *dev;
	__be16 *eh;

	/* EtherIP ヘッダ(2B) が来ているか確認 */
	if (!pskb_may_pull(skb, 2))
		goto drop;

	eh = (__be16 *)skb->data;
	if (*eh != cpu_to_be16(EIP_HDR_BE16))
		goto drop;

	rcu_read_lock();
	dev = eip_lookup_rcu_v4(net, iph->saddr);
	if (!dev) {
		rcu_read_unlock();
		goto drop;
	}

	/* EtherIP ヘッダを除去 */
	__skb_pull(skb, 2);

	/* 宛先デバイスに受信させる（Ethernet ヘッダはこの時点で先頭にある） */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev); /* ETH ヘッダを剥がしつつプロトコル設定 */

	/* 統計更新 */
	{
		struct eip_priv *p = netdev_priv(dev);
		p->rx_pkts++;
		p->rx_bytes += skb->len;
	}
	rcu_read_unlock();

	netif_rx(skb);
	return NET_RX_SUCCESS;

drop:
	/* 不正/対象なしは破棄。 */
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int eip_ipv6_rcv(struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct net *net = dev_net(skb->dev);
	struct net_device *dev;
	__be16 *eh;

	if (!pskb_may_pull(skb, 2))
		goto drop;

	eh = (__be16 *)skb->data;
	if (*eh != cpu_to_be16(EIP_HDR_BE16))
		goto drop;

	rcu_read_lock();
	dev = eip_lookup_rcu_v6(net, &ip6h->saddr);
	if (!dev) {
		rcu_read_unlock();
		goto drop;
	}

	__skb_pull(skb, 2);

	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);

	{
		struct eip_priv *p = netdev_priv(dev);
		p->rx_pkts++;
		p->rx_bytes += skb->len;
	}
	rcu_read_unlock();

	netif_rx(skb);
	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/* IPv4/IPv6 のプロトコル登録子（Protocol=97 をフック） */
static const struct net_protocol eip_v4_proto = {
	.handler   = eip_ipv4_rcv,
	.no_policy = 1,
	.netns_ok  = 1,
};

static const struct inet6_protocol eip_v6_proto = {
	.handler = eip_ipv6_rcv,
	.flags   = INET6_PROTO_NOPOLICY,
};

/* -------- モジュール初期化/終了 --------------------------------------- */

static int __init eip_init(void)
{
	int rc;

	rc = register_pernet_subsys(&eip_pernet_ops);
	if (rc)
		return rc;

	rc = inet_add_protocol(&eip_v4_proto, IPPROTO_ETHERIP);
	if (rc) {
		unregister_pernet_subsys(&eip_pernet_ops);
		return rc;
	}

	rc = inet6_add_protocol(&eip_v6_proto, IPPROTO_ETHERIP);
	if (rc) {
		inet_del_protocol(&eip_v4_proto, IPPROTO_ETHERIP);
		unregister_pernet_subsys(&eip_pernet_ops);
		return rc;
	}

	pr_info(EIP_DRV_NAME ": loaded (version %s)\n", EIP_DRV_VERSION);
	return 0;
}

static void __exit eip_exit(void)
{
	inet6_del_protocol(&eip_v6_proto, IPPROTO_ETHERIP);
	inet_del_protocol(&eip_v4_proto, IPPROTO_ETHERIP);
	unregister_pernet_subsys(&eip_pernet_ops);
	pr_info(EIP_DRV_NAME ": unloaded\n");
}

module_init(eip_init);
module_exit(eip_exit);
```

---

## `Makefile`

> **ビルド方法**は「カーネルツリー内に組み込む」方法と「外部モジュール(out-of-tree)としてビルドする」方法の両方を示します。以下の `Makefile` は **外部モジュール**用です。

```make
# 外部モジュールとしてビルドするための Makefile
# 例:  make -C /lib/modules/$(uname -r)/build M=$(PWD) modules

obj-m += eip.o
eip-y := eip_main.o

# 参考: カーネルツリーへ組み込む場合は drivers/net/eip/ に配置し、
# drivers/net/Makefile / Kconfig を編集（下記 README を参照）。
```

---

## `Kconfig`

> **カーネルツリーへ組み込む**場合に使います。`drivers/net/` に置いてください。

```text
config ETHERIP_EIP
	tristate "EtherIP (RFC3378) virtual device (eipX)"
	depends on INET && IPV6
	help
	  Provide a simple EtherIP (IP protocol 97) virtual device driver.
	  Interfaces are created via /proc/sys/net/eip/create and configurable
	  via /proc/sys/net/eip/eipX/{peer,mac}.
	  Say M to build as a module (eip.ko).
```

---

## `README.md`

````markdown
# eip: EtherIP (RFC3378) Virtual Device for Linux 6.8

## 概要
`eip0`, `eip1`, ... といった名前の仮想 Ethernet デバイスを作り、L2 フレームを
EtherIP (IP プロトコル 97) でカプセル化して既存の IP スタックで送受信します。

- 作成・設定は `/proc/sys/net/eip/` 配下の **sysctl 風コントロールファイル**で行います。
- 読み取りは誰でも可、書き込みは root 限定のパーミッション (0644) です。

## ビルドと導入

### 1) 外部モジュール (out-of-tree) としてビルド
```bash
git clone <本ディレクトリ> eip
cd eip
make -C /lib/modules/$(uname -r)/build M=$PWD modules
sudo insmod eip.ko
# or: sudo modprobe ./eip.ko
````

### 2) カーネルツリーに組み込む

1. 本ディレクトリをツリーへコピー: `drivers/net/eip/`
2. `drivers/net/Makefile` に追記:

   ```
   obj-$(CONFIG_ETHERIP_EIP) += eip/
   ```
3. `drivers/net/Kconfig` に追記:

   ```
   source "drivers/net/eip/Kconfig"
   ```
4. `make menuconfig` で
   `Device Drivers -> Network device support -> EtherIP (RFC3378) virtual device (eipX)`
   を `M` または `Y` にし、ビルド。

## 使い方

### 1) デバイスの作成

```bash
# root で:
echo new | sudo tee /proc/sys/net/eip/create
# 直近に作られた名前を確認（例: eip0）
cat /proc/sys/net/eip/create
```

### 2) 宛先 IP (peer) と MAC の設定

```bash
# 宛先 IP は IPv4/IPv6 いずれも可
echo 203.0.113.10 | sudo tee /proc/sys/net/eip/eip0/peer
# あるいは IPv6
echo 2001:db8::1 | sudo tee /proc/sys/net/eip/eip0/peer

# MAC は 12 桁 HEX（コロン区切りも許容）
echo 001122334455 | sudo tee /proc/sys/net/eip/eip0/mac
# 表示
cat /proc/sys/net/eip/eip0/peer
cat /proc/sys/net/eip/eip0/mac
```

### 3) インターフェイスを UP

```bash
sudo ip link set dev eip0 up
# 必要なら L3 アドレス設定やブリッジへの参加も可
sudo ip addr add 192.0.2.100/24 dev eip0
# 例: ブリッジへ
# sudo ip link add name br0 type bridge
# sudo ip link set eip0 master br0
# sudo ip link set br0 up
```

### 4) 動作の考え方

* `eip0` に上位が L2 フレームを送ると、ドライバは EtherIP ヘッダ(0x3000)を付け
  て、**IP プロトコル 97 の Raw パケット**として `peer` へ送信します。
* 受信側ホストで EtherIP パケットを IP スタックが受理すると、ドライバがフックし、
  **送信元アドレスが当該 `eipX` の `peer` と一致する場合のみ**デカプセル化して、
  まるで `eipX` が L2 フレームを受信したかのように上位へ渡します。

> 注意: 本実装は学習/検証用途の最小機能です。実運用では以下のような点の強化を検討してください:
>
> * MTU とフラグメンテーションの最適化（パス MTU 探索/PMTUD）
> * 複数 `eipX` が同一 peer を向く場合の配送ポリシー（現実装は最初に一致した1つに配送）
> * XFRM/IPsec 等のポリシー連携、ルーティング/マークの扱い
> * 統計・エラー処理の充実、デバイス削除・再設定の際の同期など

## テストのヒント

* 送信側 / 受信側の両方で `eipX/peer` を相手の IP アドレスに設定してください。
* `tcpdump` で EtherIP を確認:

  ```bash
  sudo tcpdump -i <IP側IF> ip proto 97
  sudo tcpdump -i <IP側IF> ip6 proto 97
  ```

````

---

## 実装の要点（補足解説）

- **プロトコル登録**  
  IPv4/IPv6 ともに **プロトコル番号 97** を `inet_add_protocol()` / `inet6_add_protocol()` でフック。  
  受信ハンドラでは EtherIP ヘッダ `0x3000`（Version=3, Reserved=0）を検査します。

- **送信**  
  `ndo_start_xmit` では、SKB を線形化したあと **カーネル空間の RAW ソケット**（`SOCK_RAW / IPPROTO_ETHERIP`）に対し、  
  `kvec` を使って **[ EtherIP 2 バイト ] + [ Ethernet フレーム本体 ]** を一括 `kernel_sendmsg()`。  
  IP ヘッダは **カーネル側で生成**されるため、経路選択や分割は IP スタックに委譲します。

- **受信**  
  IP スタックのローカル配送フェーズで EtherIP ペイロードに到達した時点で呼ばれ、  
  送信元アドレスが `peer` と一致する `eipX` を netns 内から探索して配送します。  
  `eth_type_trans()` により Ethernet ヘッダを剥がし、上位へ渡しています。

- **コントロールファイル（sysctl）**  
  `/proc/sys/net/eip/create` に書き込むと新規デバイスを作成し、直近作成された IF 名を読み出せます。  
  作成されたデバイスごとに `/proc/sys/net/eip/<ifname>/{peer,mac}` が現れ、読み出しは誰でも可、  
  設定（書き込み）は root のみ可（0644）。  
  *peer* は `IPv4` または `IPv6` の ASCII、*mac* は `001122334455`（コロン区切りも許容）。

---

## 注意 / 既知の制限

- **MTU/フラグメンテーション**: 簡易実装のため `eipX` の MTU は 1500 のままです。外側 IP ヘッダと EtherIP ヘッダぶんオーバーヘッドが増えるため、パスによっては IP 断片化が発生します。実運用では PMTUD 等の導入を推奨します。
- **複数一致の扱い**: 同一 `peer` を向く `eipX` が複数ある場合、最初に見つかった 1 つにのみ配送します。
- **削除/再作成**: 最小実装のため `/proc/sys/net/eip/` からの **削除コマンド**は提供していません。不要になったら `ip link set eipX down` と `rmmod eip`（またはネットネームスペース破棄）で対応してください。
- **セキュリティ**: EtherIP は暗号化や認証を提供しません。機微データには IPsec 等の併用をご検討ください。

---

### 使い方（簡易例）

```bash
# 送出側ホスト (A)
sudo modprobe ./eip.ko
echo new | sudo tee /proc/sys/net/eip/create     # => eip0
echo 203.0.113.2 | sudo tee /proc/sys/net/eip/eip0/peer
echo 001122334455 | sudo tee /proc/sys/net/eip/eip0/mac
sudo ip link set eip0 up

# 受信側ホスト (B)
sudo modprobe ./eip.ko
echo new | sudo tee /proc/sys/net/eip/create     # => eip0
echo 203.0.113.1 | sudo tee /proc/sys/net/eip/eip0/peer
echo aabbccddeeff | sudo tee /proc/sys/net/eip/eip0/mac
sudo ip link set eip0 up

# 以後、A の eip0 から送った L2 フレームは EtherIP で B 宛に送られ、B の eip0 に届く
````

---

以上のファイルをそのまま配置・ビルドしていただければ、要件に沿った **EtherIP 仮想デバイス**が利用できます。必要に応じて MTU や配送ポリシーなどを拡張してください。
