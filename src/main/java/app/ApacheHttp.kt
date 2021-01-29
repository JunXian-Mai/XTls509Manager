package app

import bj.anydef.tls.cert.manager.AnydefX509TrustManager
import org.apache.http.HttpHost
import org.apache.http.HttpServerConnection
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.message.BasicHttpRequest
import javax.net.ssl.*

class ApacheHttp {
  companion object {
    fun doGet() {
      val url = "https://www.jianshu.com/"
      val sslContext = SSLContext.getInstance("TLSv1.2")
      sslContext.init(null, arrayOf(AnydefX509TrustManager()), null)
      val httpClient = HttpClientBuilder.create().setSSLContext(sslContext).build()
      val httpGet = HttpGet(url)
      val response = httpClient.execute(httpGet)
      println("""
        statusLine: ${response.statusLine}
      """.trimIndent())
    }

    fun emqxTLSLink() {
      val sslContext = SSLContext.getInstance("TLSv1.2")
      sslContext.init(null, arrayOf(AnydefX509TrustManager()), null)
      val httpClient = HttpClientBuilder.create().setSSLContext(sslContext).build()
      val httpGet = HttpGet("https://127.0.0.1:8883/")
      val response = httpClient.execute(httpGet)
      println("""
        statusLine: ${response.statusLine}
      """.trimIndent())
    }

    @JvmStatic
    fun main(args: Array<String>) {
      emqxTLSLink()
    }
  }
}
