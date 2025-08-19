# EtherIP カーネルモジュール Makefile

# モジュール名
obj-m := etherip.o

# ソースファイル
etherip-objs := etherip.o

# カーネルソースディレクトリ（デフォルト）
KDIR ?= /lib/modules/$(shell uname -r)/build

# 現在のディレクトリ
PWD := $(shell pwd)

# ビルドターゲット
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# クリーンターゲット
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.* .*.cmd Module.symvers modules.order

# インストールターゲット
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# アンインストールターゲット
uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/etherip.ko
	depmod -a

# モジュールロード
load:
	sudo insmod etherip.ko

# モジュールアンロード
unload:
	sudo rmmod etherip

# ヘルプ
help:
	@echo "使用可能なターゲット:"
	@echo "  all       - モジュールをビルド"
	@echo "  clean     - ビルド生成物をクリーン"
	@echo "  install   - モジュールをインストール"
	@echo "  uninstall - モジュールをアンインストール"
	@echo "  load      - モジュールをロード"
	@echo "  unload    - モジュールをアンロード"

.PHONY: all clean install uninstall load unload help