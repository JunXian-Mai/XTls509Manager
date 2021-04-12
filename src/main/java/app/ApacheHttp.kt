package app

import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
import org.markensic.xtls.etc.XTlsFactory
import org.markensic.xtls.manager.XTlsHostVerifier
import java.security.SecureRandom
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

class ApacheHttp {
  companion object {

    @JvmStatic
    fun main(args: Array<String>) {
      doGet()
    }

    fun doGet() {
      val url = "https://127.0.0.1:8443/"
      val httpClient = HttpClientBuilder.create()
        .setSSLContext(getSSlContext(true))
        .setSSLHostnameVerifier(XTlsHostVerifier(XTls509CertSetImpl))
        .build()
      val httpGet = HttpGet(url)
      val response = httpClient.execute(httpGet)
      println(
        """
          statusLine: ${response.statusLine}
        """.trimIndent()
      )
    }

    fun getSSlContext(mutual: Boolean = true): SSLContext {
      val trustManager = XTlsFactory.creatDefaultManager(XTls509CertSetImpl)
//      val trustManager = TrustAllManager()
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        keyManager = XTlsFactory.getKeyManagerFactory(
          XTls509CertSetImpl.getClientKeyCertPathPairs()[0]
        )
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(if (mutual) keyManager?.keyManagers else null, arrayOf(trustManager), SecureRandom())
      return context
    }
  }
}
