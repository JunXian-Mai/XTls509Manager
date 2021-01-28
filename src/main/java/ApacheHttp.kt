import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
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

    @JvmStatic
    fun main(args: Array<String>) {
      doGet()
    }
  }
}
