# 既存の SSL/TLS サーバーに対する OpenSSL 1.1 および 3.0 での接続テスト方法
既存の SSL/TLS サーバーに対して、OpenSSL 1.1 からの接続に成功するが、OpenSSL 3.0 からの接続に失敗する現象が存在し得る。特定の既存の SSL/TLS サーバーにおいて、そのような問題が存在しているかどうかを確認する必要がある場合がある。


そこで、既存の SSL/TLS サーバーが存在する場合において、OpenSSL 1.1 と OpenSSL 3.0 からの接続に成功するか否かをテストする手段を、以下のドキュメントとしてまとめる。


## 前提条件
以下のドキュメントでは、テスト対象の SSL/TLS サーバーが、プライベート IPv4 アドレス `1.2.3.4` で、TCP ポート `443` (HTTPS) で動作していると仮定する。実際の環境のアドレスおよびポートの文字列に置換して実行すること。

## テストに必要な環境
クライアントとして Windows マシンが 1 台必要である。


Windows XP 以降であれば動作すると考えられる。

## 必要なファイルのダウンロード
以下の ZIP ファイルをダウンロードする。


**https://lts.dn.cyber.ipa.go.jp/d/211117_002_lts_openssl_exesuite_09221/211117/lts_openssl_exesuite/windows_x64/_download_zip/**


これを展開すると、

```
lts_openssl_exesuite_0.9.8zh.exe
lts_openssl_exesuite_1.0.2u.exe
lts_openssl_exesuite_1.1.1l.exe
lts_openssl_exesuite_3.0.0.exe
```

という 4 つの EXE ファイルが出てくる。これらが、それぞれのバージョンの OpenSSL のテストツールを Visual C++ でビルドしたものである。


## テスト 1. OpenSSL 1.1 でのテスト
Windows のコマンドプロンプト (cmd) から、


### テスト 1-1 (OpenSSL 1.1 で TLS 1.3)
```

lts_openssl_exesuite_1.1.1l.exe s_client -connect 1.2.3.4:443 -showcerts -tls1_3

```

と実行する。なお、SSL/TLS の接続に正常に成功した場合は、上記 OpenSSL のコマンドが標準入力から入力待ち状態となって停止する。この場合は、Ctrl + C を押して、コマンドを終了すること。


### テスト 1-2 (OpenSSL 1.1 で TLS 1.2)
```

lts_openssl_exesuite_1.1.1l.exe s_client -connect 1.2.3.4:443 -showcerts -tls1_2

```

と実行する。なお、SSL/TLS の接続に正常に成功した場合は、上記 OpenSSL のコマンドが標準入力から入力待ち状態となって停止する。この場合は、Ctrl + C を押して、コマンドを終了すること。

### テスト 1-3 (OpenSSL 1.1 で TLS バージョン指定なし)
```

lts_openssl_exesuite_1.1.1l.exe s_client -connect 1.2.3.4:443 -showcerts

```

と実行する。なお、SSL/TLS の接続に正常に成功した場合は、上記 OpenSSL のコマンドが標準入力から入力待ち状態となって停止する。この場合は、Ctrl + C を押して、コマンドを終了すること。






## テスト 2. OpenSSL 3.0 でのテスト
Windows のコマンドプロンプト (cmd) から、


### テスト 2-1 (OpenSSL 3.0 で TLS 1.3)
```

lts_openssl_exesuite_3.0.0.exe s_client -connect 1.2.3.4:443 -showcerts -tls1_3

```

と実行する。なお、SSL/TLS の接続に正常に成功した場合は、上記 OpenSSL のコマンドが標準入力から入力待ち状態となって停止する。この場合は、Ctrl + C を押して、コマンドを終了すること。

### テスト 2-2 (OpenSSL 3.0 で TLS 1.2)
```

lts_openssl_exesuite_3.0.0.exe s_client -connect 1.2.3.4:443 -showcerts -tls1_2

```

と実行する。なお、SSL/TLS の接続に正常に成功した場合は、上記 OpenSSL のコマンドが標準入力から入力待ち状態となって停止する。この場合は、Ctrl + C を押して、コマンドを終了すること。

### テスト 2-3 (OpenSSL 3.0 で TLS バージョン指定なし)
```

lts_openssl_exesuite_3.0.0.exe s_client -connect 1.2.3.4:443 -showcerts

```

と実行する。なお、SSL/TLS の接続に正常に成功した場合は、上記 OpenSSL のコマンドが標準入力から入力待ち状態となって停止する。この場合は、Ctrl + C を押して、コマンドを終了すること。

## テスト結果のまとめ

上記の各テスト結果をテキストファイル等にまとめて、何か重要な違いがあるか、特定のバージョンからの接続に失敗するか等の差異を目視で確認する。




