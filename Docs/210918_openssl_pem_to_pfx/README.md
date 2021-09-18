# OpenSSL を用いた SSL 証明書 (中間証明書チェーン付き) および秘密鍵の PEM 形式から PKCS#12 (.pfx) 形式への変換方法
`2021/09/18 登`


- 商用証明書プロバイダー (認証局) から購入した SSL 証明書 (中間証明書チェーン付き) は、多くの場合、PEM 形式 (BASE64 形式) である。
- これを PKCS#12 (.pfx) 形式へ変換するためには、OpenSSL コマンドを使用すれば良いのであるが、コマンドの指定方法をよく忘れるのである。
- そこで、本文書では、OpenSSL を用いた SSL 証明書 (中間証明書チェーン付き) および秘密鍵の PEM 形式から PKCS#12 (.pfx) 形式への変換方法を明確に記載するのである。
- 以下のコマンドは、PKCS#12 ファイルを生成するが、パスワードは設定しない。多くの Web サーバーフトウェアでは、暗号化された .pfx ファイルを読み込むことが困難なので、以下の方法でパスワードを設定せず作成した .pfx ファイルをそのまま指定することができる。
- また、本文書の後半では、逆に .pfx ファイルを元に中の証明書チェーンと秘密鍵を個別のファイルとして取り出す方法についても解説をする。


# 元のファイル一覧 (前提)
以下の 3 つのファイルがカレントディレクトリに存在すると仮定する。


## 1. 「cert.key」ファイル - 証明書本体
これは、よくある `-----BEGIN CERTIFICATE-----` および `-----END CERTIFICATE-----` で囲まれた 1 つの BASE64 エンコードされた X.509 証明書ファイルである。

## 2. 「cert.key」ファイル - 秘密鍵
これは、`cert.key` ファイルに対応した RSA 秘密鍵ファイルである。`-----BEGIN RSA PRIVATE KEY-----` および `-----END RSA PRIVATE KEY-----` で囲まれた秘密鍵が 1 つだけ入っている。

## 3. 「chain.cer」ファイル - 中間証明書チェーン
これは、1 つまたは 2 つ以上の `-----BEGIN CERTIFICATE-----` および `-----END CERTIFICATE-----` で囲まれた BASE64 エンコードされた X.509 証明書ファイルが、1 つのテキストファイルに並んで入っているファイルである。多くの場合、SSL 証明書を購入した際の納品物に含まれているか、または、CA の Web サイトに陳列されている。


なお、1. と 3. の証明書類が 1 つに合体した形式も散見される。この場合は、たいていの場合、その合体された証明書ファイル (テキストファイル) の先頭の証明書が「1.」に相当するもので、2 つ目以降の証明書が「3.」に相当するものである。このような場合は、任意のテキストエディタを用いて「1.」と「3.」に分離して保存すること。


# OpenSSL による PEM → PFX の変換コマンド (お待ちかね)
以下のコマンドで、上記の 1 + 2 + 3 の証明書および秘密鍵を結合して、1 つの PFX ファイルに変換することができるのである。
```

openssl pkcs12 -export -nodes -inkey cert.key -in cert.cer -certfile chain.cer -out result.pfx -passout pass:

```

上記を実行すると、`result.pfx` ファイルが生成される。


# 生成された result.pfx ファイルの中身の確認 (参考)
Windows であれば、右クリックして「開く」をクリックすると、わかりやすい GUI で証明書の中身が表示される。


また、OpenSSL コマンドを使用する場合は、以下の方法で確認できる。

```

openssl pkcs12 -info -in result.pfx -nodes -passin pass:

```


# PKCS#12 ファイル (生成された result.pfx ファイル等) から中身の証明書チェーンと秘密鍵をファイルとして取り出す方法 (参考)
以下を実行すると、`result.pfx` ファイルを元に、中に格納されている証明書チェーンを `extraced_certs.cer` ファイル、秘密鍵を `extraced_key.key` ファイル、秘密鍵を元の RSA 秘密鍵形式に復元したものを `extraced_key.key` ファイルとして保存することができる。

```

openssl pkcs12 -in result.pfx -nokeys -out extraced_certs.cer -nodes -passin pass: -passout pass:

openssl pkcs12 -in result.pfx -nocerts -out extraced_key.key -nodes -passin pass: -passout pass:

openssl rsa -in extraced_key.key -out extraced_rsa_key.key

```

ホストの証明書と、中間証明書チェーンとが、連結されて 1 つのファイルとして出力されてしまうが、これはテキストエディタを用いて容易に分離できる。また、これを OpenSSL コマンドを用いて分離する方法については、本文書の著者は不知である。



## 糸冬了！！
