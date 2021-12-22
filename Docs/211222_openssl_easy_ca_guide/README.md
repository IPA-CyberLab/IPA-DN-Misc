# X.509 証明書の RSA ルート CA 証明書およびそのルート CA によって署名されるサーバー証明書の OpenSSL コマンドを用いた簡易的な作成方法の説明書

このファイルは、X.509 証明書の RSA ルート CA 証明書およびそのルート CA によって署名されるサーバー証明書の OpenSSL コマンドを用いた簡易的な作成方法の説明書です。


どなたでも、OpenSSL、X.509 証明所および PKI に関する基本的な知識を有していれば、以下の方法で同じように証明書を作成可能です。


## ルート CA 証明書類 (01_easy_root_ca) の作成方法

### まず、ルート証明書用の秘密鍵を作成します。

```

openssl genrsa 2048 > 01_easy_root_ca.key

```

### 次に、作成したルート証明書の秘密鍵に基づくルート証明書を作成します。ルート証明書に埋め込まれる Subject 名などの文字列属性は、ここで設定します。

```
openssl req -new -x509 -nodes -days 20000 -key 01_easy_root_ca.key -sha256 > 01_easy_root_ca.cer
Country Name (2 letter code) [AU]: JP
State or Province Name (full name) [Some-State]: Tokyo
Locality Name (eg, city) []: Tokyo
Organization Name (eg, company) [Internet Widgits Pty Ltd]: EasySampleCA
Organizational Unit Name (eg, section) []:
Common Name (eg, YOUR name) []: EasySampleCA
Email Address []:
```


## サーバー証明書類 (02_easy_server_cert) の作成方法

### まず、サーバー証明書用の秘密鍵を作成します。

```

openssl genrsa 2048 > 02_easy_server_cert.key

```

### 次に、サーバー証明書に設定するべき属性ファイルを記述します。通常は、以下のままで OK です。

```

cat <<\EOF > 02_easy_server_cert.config
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign, cRLSign
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
EOF

```

### そして、サーバー証明書の発行要求ファイル (CSR) を作成します。サーバー証明書に埋め込まれる Subject 名などの文字列属性は、ここで設定します。

```

openssl req -new -key 02_easy_server_cert.key -out 02_easy_server_cert.csr
Country Name (2 letter code) [AU]: JP
State or Province Name (full name) [Some-State]: Tokyo
Locality Name (eg, city) []: Tokyo
Organization Name (eg, company) [Internet Widgits Pty Ltd]: EasySampleServerCert
Organizational Unit Name (eg, section) []:
Common Name (eg, YOUR name) []: EasySampleServerCert
Email Address []:
A challenge password []:
An optional company name []:

```

### CSR に基づき、サーバー証明書を発行します。

```

openssl x509 -req -in 02_easy_server_cert.csr -CA 01_easy_root_ca.cer -CAkey 01_easy_root_ca.key -days 19000 -set_serial 1 -sha256 -extfile 02_easy_server_cert.config > 02_easy_server_cert.cer

```

### (参考: PKCS#12 形式への変換) 発行されたサーバー証明書は、X.509 PEM 形式であり、このままではほとんどの Web ブラウザ (Internet Explorer, Chrome, Firefox 等) でインポートすることができません。そこで、PKCS#12 形式 (1 つのバイナリファイルに証明書と秘密鍵の両方が格納されている形式) に変換します。なお、パスフレーズは、サンプルのため空文字にしていますが、設定することも可能です。

```

openssl pkcs12 -export -in 02_easy_server_cert.cer -inkey 02_easy_server_cert.key > 02_easy_server_cert.pfx -passout pass:

```


