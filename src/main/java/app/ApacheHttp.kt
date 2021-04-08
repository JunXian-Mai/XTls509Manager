package app

import bj.anydef.tls.cert.etc.X509ManagerEtc
import bj.anydef.tls.cert.manager.HostnameVerifier
import bj.anydef.tls.cert.manager.X509TrustManager
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
      val url = "https://127.0.0.1:8443/"
      val httpClient = HttpClientBuilder.create()
        .setSSLContext(getSSlContext(true))
        .setSSLHostnameVerifier(HostnameVerifier)
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
      val trustManager = X509TrustManager()
//      val trustManager = TrustAllManager()
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        keyManager = X509ManagerEtc.getKeyManagerFactory()
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(if (mutual) keyManager?.keyManagers else null, arrayOf(trustManager), SecureRandom())
      return context
    }
  }
}
