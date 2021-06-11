package org.markensic.xtls

import org.markensic.xtls.etc.Source
import org.markensic.xtls.manager.XTlsFactoryManager
import org.markensic.xtls.hostname.XTlsHostVerifier
import org.markensic.xtls.manager.XTls509TrustManager

class XTlsTrustManagerBuilder(
  val source: Source,
  val hostname: XTlsHostVerifier) {

  // 是否添加系统默认信任证书
  private var attach: Boolean = true
  // 导入信任的公钥路径列表
  private val caCertPaths: MutableList<String> = mutableListOf()
  // 导入信任的公钥内容列表
  private val caCertContents: MutableList<String> = mutableListOf()

  fun attachSystemCerts(attach: Boolean): XTlsTrustManagerBuilder {
    return apply {
      this.attach = attach
    }
  }

  fun addAllPath(list: List<String>): XTlsTrustManagerBuilder {
    return apply {
      this.caCertPaths.addAll(list)
    }
  }

  fun addPath(path: String): XTlsTrustManagerBuilder {
    return apply {
      this.caCertPaths.add(path)
    }
  }

  fun addAllContent(list: List<String>): XTlsTrustManagerBuilder {
    return apply {
      this.caCertContents.addAll(list)
    }
  }

  fun addContent(content: String): XTlsTrustManagerBuilder {
    return apply {
      this.caCertContents.add(content)
    }
  }

  fun build(): XTls509TrustManager {
    return when (source) {
      is Source.PATH -> XTls509TrustManager(XTlsFactoryManager.getCaCertificates(caCertPaths.toTypedArray()), hostname, attach)
      is Source.CONTENT -> XTls509TrustManager(XTlsFactoryManager.convertCaCertificates(caCertContents.toTypedArray()), hostname, attach)
    }
  }
}
