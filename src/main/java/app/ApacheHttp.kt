package app

import bj.anydef.tls.cert.etc.AnydefX509ManagerEtc
import bj.anydef.tls.cert.manager.AnydefHostnameVerifier
import bj.anydef.tls.cert.manager.AnydefX509TrustManager
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
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
      val url = "https://www.baidu.com/"
      val httpClient = HttpClientBuilder.create()
        .setSSLContext(getSSlContext(true))
        .setSSLHostnameVerifier(AnydefHostnameVerifier)
        .build()
      val httpGet = HttpGet(url)
      val response = httpClient.execute(httpGet)
      println(
        """
          statusLine: ${response.statusLine}
        """.trimIndent())
    }

    fun getSSlContext(mutual: Boolean = true): SSLContext {
      val trustManager = AnydefX509TrustManager()
//      val trustManager = TrustAllManager()
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        keyManager = AnydefX509ManagerEtc.getKeyManagerFactory()
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(if (mutual) keyManager?.keyManagers else null, arrayOf(trustManager), SecureRandom())
      return context
    }
  }
}
