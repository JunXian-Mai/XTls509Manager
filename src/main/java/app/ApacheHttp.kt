package app

import bj.anydef.tls.cert.etc.AnydefX509ManagerEtc
import bj.anydef.tls.cert.manager.AnydefHostnameVerifier
import bj.anydef.tls.cert.manager.AnydefX509TrustManager
import org.apache.http.HttpHost
import org.apache.http.HttpServerConnection
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.message.BasicHttpRequest
import java.security.SecureRandom
import javax.net.ssl.*

class ApacheHttp {
  companion object {
    fun doGet() {
      val url = "https://localhost:8443/"
      val httpClient = HttpClientBuilder.create()
        .setSSLContext(getSSlContext(false))
        .setSSLHostnameVerifier(AnydefHostnameVerifier)
        .build()
      val httpGet = HttpGet(url)
      val response = httpClient.execute(httpGet)
      println("""
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

    @JvmStatic
    fun main(args: Array<String>) {
      doGet()
    }
  }
}
