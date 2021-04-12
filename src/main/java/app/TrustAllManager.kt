package app

import java.security.cert.X509Certificate

class TrustAllManager() : javax.net.ssl.X509TrustManager {
  private val issuers: Array<X509Certificate> = arrayOf()

  override fun getAcceptedIssuers(): Array<X509Certificate> {
    return issuers
  }

  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String?) {}

  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?) {}
}
