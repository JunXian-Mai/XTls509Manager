# XTls509Manager
## Introduce
Java - 自定义客户端X509证书管理器

详细用法见Demo/app

---
jar包结构及说明：

org.markensic.xtls.impl.XTls509CertSet: X509密钥路径集合

org.markensic.xtls.etc.XTls509ManagerEtc：X509配置

org.markensic.xtls.manager.XTls509TrustManager: X509证书管理器

org.markensic.xtls.manager.XTlsHostVerifier: X509域名校验管理器

---
简单使用步骤：

1.实现 XTls509CertSet，配置客户端密钥

2.利用 XTls509CertSet，创建 XTls509ManagerEtc

3.1 利用 ETC 创建 XTls509TrustManager

3.2 利用 ETC 创建 XTlsHostVerifier

4 创建SSLContext

``` SSLContext
    fun getSSlContext(mutual: Boolean = true): SSLContext {
      val trustManager = XTls509TrustManager(etc)
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        keyManager = etc.getKeyManagerFactory()
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(if (mutual) keyManager?.keyManagers else null, arrayOf(trustManager), SecureRandom())
      return context
    }
```

5 导入SSLContex到对应的 Client




