# XTls509Manager 2.0

## Introduce

Java - 自定义客户端X509证书管理器

详细用法见Demo/app

---
jar包结构及说明：

org.markensic.xtls.manager.XTlsFactoryManager：X509配置工厂管理器

org.markensic.xtls.manager.XTls509TrustManager: X509证书管理器

org.markensic.xtls.hostname.XTlsHostnameConfig: X509域名验证过滤配置

org.markensic.xtls.hostname.XTlsHostVerifier: X509域名校验管理器

org.markensic.xtls.etc.Source: 构建器中证书与密钥来源
org.markensic.xtls.XTlsTrustManagerBuilder: X509证书管理器构建器
org.markensic.xtls.XTlsKeyManagerBuilder: X509客户端证书密钥构建器

---
简单使用步骤：

1.实现 XTlsHostnameConfig, 配置域名校验过滤

2.初始化 XTlsTrustManagerBuilder, XTlsKeyManagerBuilder

3.利用 XTlsHostnameConfig 初始化 XTlsHostVerifier, 构建域名校验器

4.使用 XTlsTrustManagerBuilder 配置证书, 域名校验过滤器, 构建X509证书管理器

5.利用 XTlsKeyManagerBuilder 构建客户端证书密钥管理器

4.创建SSLContext

``` SSLContext
    fun getSSlContext(mutual: Boolean = true): SSLContext {
      val trustManager = trustBuilder
        .addPath("/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-my.crt")
        .attachSystemCerts(true)
        .build()
//      val trustManager = TrustAllManager()
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        keyManager = keyBuilder
          .addClientKeyPath(
            "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/clientmy.crt",
            "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem")
          .build()
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(if (mutual) keyManager?.keyManagers else null, arrayOf(trustManager), SecureRandom())
      return context
    }
```

5.导入SSLContex到对应的 Client

6.选配 XTlsHostVerifier(XTlsHostnameConfig) 域名校验器




