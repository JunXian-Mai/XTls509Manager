package org.markensic.xtls

import org.markensic.xtls.etc.Source
import org.markensic.xtls.manager.XTlsFactoryManager
import javax.net.ssl.KeyManagerFactory

class XTlsKeyManagerBuilder(val source: Source) {

  // 密钥密码
  private var password = ""
  // 客户端证书路径
  private var clientCertPath = ""
  // 客户端密钥路径
  private var clientKeyPath = ""
  // 客户端证书内容
  private var clientCertContent = ""
  // 客户端密钥内容
  private var clientKeyContent = ""

  fun setPassword(password: String): XTlsKeyManagerBuilder {
    return apply {
      this.password = password
    }
  }

  fun addClientKeyPath(certPath: String, keyPath: String): XTlsKeyManagerBuilder {
    return apply {
      this.clientCertPath = certPath
      this.clientKeyPath = keyPath
    }
  }

  fun addClientKeyContent(certContent: String, keyContent: String): XTlsKeyManagerBuilder {
    return apply {
      this.clientCertContent = certContent
      this.clientKeyContent = keyContent
    }
  }

  fun build(): KeyManagerFactory {
    return when (source) {
      is Source.PATH -> XTlsFactoryManager.getKeyManagerFactory(clientCertPath, clientKeyPath, password)
      is Source.CONTENT -> XTlsFactoryManager.convertKeyManagerFactory(clientCertContent, clientKeyContent, password)
      else -> throw IllegalArgumentException("Type 'NONE' can't build KeyManagerFactory")
    }
  }
}
