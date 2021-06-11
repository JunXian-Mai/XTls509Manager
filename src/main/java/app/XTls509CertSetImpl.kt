package app

import org.markensic.xtls.hostname.XTlsHostnameConfig


object XTls509CertSetImpl : XTlsHostnameConfig {
  override fun getIgnoreTargetIPVerifierList(): Array<String> {
    return arrayOf(
      ""
    )
  }

  override fun getIgnoreTargetHostVerifierList(): Array<String> {
    return arrayOf(
      ""
    )
  }

  override fun getIgnoreAccessIPVerifierList(): Array<String> {
    return arrayOf(
      "127.0.0.1"
    )
  }

  override fun getIgnoreAccessHostVerifierList(): Array<String> {
    return arrayOf(
      "127.0.0.1"
    )
  }
}
