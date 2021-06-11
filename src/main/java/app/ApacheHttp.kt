package app

import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
import org.markensic.xtls.XTlsKeyManagerBuilder
import org.markensic.xtls.XTlsTrustManagerBuilder
import org.markensic.xtls.etc.Source
import org.markensic.xtls.hostname.XTlsHostVerifier
import java.security.SecureRandom
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

class ApacheHttp {
  companion object {
    val hostname = XTlsHostVerifier(XTls509CertSetImpl)

    val trustBuilder = XTlsTrustManagerBuilder(
      Source.PATH(),
      hostname)

    val keyBuilder = XTlsKeyManagerBuilder(Source.PATH())

    @JvmStatic
    fun main(args: Array<String>) {
      doGet()
    }

    fun doGet() {
      val url = "https://127.0.0.1:8443/"
      val httpClient = HttpClientBuilder.create()
        .setSSLContext(getSSlContext(true))
        .setSSLHostnameVerifier(hostname)
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
  }
}
