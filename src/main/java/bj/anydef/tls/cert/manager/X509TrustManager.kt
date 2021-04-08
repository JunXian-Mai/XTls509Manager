package bj.anydef.tls.cert.manager

import bj.anydef.tls.cert.etc.X509ManagerEtc
import java.net.Socket
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * @param trustedSelfCerts 自定义信任证书列表
 * @param attachSystemCerts 是否添加系统默认证书
 */
class X509TrustManager(
  private val trustedSelfCerts: Array<X509Certificate> = X509ManagerEtc.getCaCertificates(),
  private val attachSystemCerts: Boolean = true
) : X509ExtendedTrustManager() {

  // [DEBUG]是否输出证书详细信息
  private val outputCertDetail = false

  // 系统默认证书信任管理器
  private val systemTrustManager = X509ManagerEtc.getSystemDefaultTrustManager();

  // 信任证书列表
  private val trustedCerts: Array<X509Certificate>

  init {
    if (attachSystemCerts) {
      trustedCerts = X509ManagerEtc.getSystemTrustedCerts()
        .plus(trustedSelfCerts)
    } else {
      trustedCerts = trustedSelfCerts
    }

    if (outputCertDetail) {
      // 输出所有信任的证书
      showTrustedCerts()
    }
  }

  override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
    checkTrusted(chain, authType, null as Socket?, true)
  }

  override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
    checkTrusted(chain, authType, null as Socket?, false)
  }

  override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket) {
    checkTrusted(chain, authType, socket, true)
  }

  override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket) {
    checkTrusted(chain, authType, socket, false)
  }

  override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine) {
    checkTrusted(chain, authType, engine, true)
  }

  override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine) {
    checkTrusted(chain, authType, engine, false)
  }

  override fun getAcceptedIssuers(): Array<X509Certificate> {
    return trustedCerts
  }

  fun getAcceptedSelfIssuers(): Array<X509Certificate> {
    return trustedSelfCerts
  }


  /**
   * 证书校验
   * @param chain 服务器证书链
   * @param authType 授权类型
   * @param socket 连接socket
   * @param checkClientTrusted 服务端否是校验客户端
   * @throws CertificateException
   */
  @Throws(CertificateException::class)
  private fun checkTrusted(
    chain: Array<out X509Certificate>?,
    authType: String?, socket: Socket?,
    checkClientTrusted: Boolean
  ) {
    // 校验服务器证书连，类型是否非NULL
    checkTrustedInit(chain, authType)

    // 判断是否是SSL,并获取SSLSession
    if (socket is SSLSocket && socket.isConnected()) {
      val session = socket.handshakeSession
      // 域名校验
      checkHostname(chain!!, session, checkClientTrusted)
    }

    // 证书校验
    checkCerts(chain!!, authType!!, checkClientTrusted)
  }

  /**
   * 证书校验
   * @param chain 服务器证书链
   * @param authType 授权类型
   * @param engine 连接engine
   * @param checkClientTrusted 服务端否是校验客户端
   * @throws CertificateException
   */
  @Throws(CertificateException::class)
  private fun checkTrusted(
    chain: Array<out X509Certificate>?,
    authType: String?, engine: SSLEngine?,
    checkClientTrusted: Boolean
  ) {
    // 校验服务器证书连，类型是否非NULL
    checkTrustedInit(chain, authType)

    // 判断engine是否非NUll,并获取SSLSession
    if (engine != null) {
      val session = engine.handshakeSession ?: throw CertificateException("No handshake session")
      // 域名校验
      checkHostname(chain!!, session, checkClientTrusted)
    }

    // 证书校验
    checkCerts(chain!!, authType!!, checkClientTrusted)
  }

  /**
   * 服务器相关参数非NULL检查
   * @param chain 证书链
   * @param authType 授权类型
   */
  @Throws(IllegalArgumentException::class)
  private fun checkTrustedInit(
    chain: Array<out X509Certificate>?,
    authType: String?
  ) {
    require(chain?.isNotEmpty() == true) { "null or zero-length certificate chain" }
    require(authType?.isNotBlank() == true) { "null or zero-length authentication type" }
  }

  /**
   * 域名校验
   * @param chain 证书链
   * @param session 会话
   * @param checkClientTrusted 是否校验客户端信任
   * @throws CertificateException 校验失败，报错
   */
  @Throws(CertificateException::class)
  private fun checkHostname(
    chain: Array<out X509Certificate>,
    session: SSLSession,
    checkClientTrusted: Boolean
  ) {
    // 生成域名校验器
    val verifier = HostnameVerifier

    // 获取访问host
    val peerHost = session.peerHost
    if (!checkClientTrusted) {
      // 获取访问host
      val sniNames = getRequestedServerNames(session)
      // 获取 SNI 域名（同主机多域名，多证书情况）
      val sniHostName = getHostNameInSNI(sniNames)
      // 存在 SNI 域名则判断 SNI 域名
      if (sniHostName?.isNotEmpty() == true) {
        // 使用域名校验器校验证书[目标证书：直接访问的证书，即chain[0]]
        if (!verifier.verify(sniHostName, chain[0])) {
          // 访问host是否匹配证书
          if (sniHostName == peerHost || !verifier.verify(peerHost!!, chain[0])) {
            // SNI 与 访问host 都不匹配，直接结束
            throw CertificateException("No subject alternative names present")
          }
        }
      } else if (peerHost != null) {
        // 不存在多域名，直接判断host
        if (!verifier.verify(peerHost, chain[0])) {
          throw CertificateException("No subject alternative names present")
        }
      }
    }
  }

  /**
   * 证书校验
   * @param chain 证书链
   * @param authType 授权类型
   * @param checkClientTrusted 是否校验客户端信任
   * @throws CertificateException 校验失败，报错
   */
  @Throws(CertificateException::class)
  private fun checkCerts(
    chain: Array<out X509Certificate>,
    authType: String,
    checkClientTrusted: Boolean
  ) {
    // 是否被自定义证书信任
    if (verifySelfCertificate(chain)) {
//      showTrustedRootCerts(chain[chain.length - 1]);
      return
    }
    if (attachSystemCerts) {
      // 使用系统默认的证书管理器校验证书
      if (checkClientTrusted) {
        systemTrustManager.checkClientTrusted(chain, authType)
      } else {
        systemTrustManager.checkServerTrusted(chain, authType)
      }
    } else {
      throw CertificateException("no certificate in root path")
    }

//    showTrustedRootCerts(chain[chain.length - 1]);
  }

  /**
   * 校验自定义证书
   * @param chain 证书链
   * @return 校验成功
   */
  private fun verifySelfCertificate(chain: Array<out X509Certificate>): Boolean {
    // 循环判断证书链是否存在自定义信任证书
    for (chainCert in chain) {
      for (cert in trustedSelfCerts) {
        try {
          chainCert.verify(cert.publicKey)
          // 某一级证书被信任，直接信任整个证书链
          return true
        } catch (e: Exception) {
          // 打印自定义证书校验失败信息
          println("self certs verify error: " + e.message)
        }
      }
    }
    // 不被自定义证书信任
    return false
  }

  // 获取 SNI
  private fun getRequestedServerNames(session: SSLSession): List<SNIServerName> {
    return if (session is ExtendedSSLSession) {
      session.requestedServerNames
    } else emptyList()
  }

  // 获取 SNI 域名
  private fun getHostNameInSNI(sniNames: List<SNIServerName>?): String? {
    var hostname: SNIHostName? = null
    sniNames?.forEach {
      if (it.type == StandardConstants.SNI_HOST_NAME) {
        if (it is SNIHostName) {
          hostname = it
        } else {
          try {
            hostname = SNIHostName(it.encoded)
          } catch (iae: IllegalArgumentException) {
            iae.printStackTrace()
            println("Illegal server name: $it")
          }
        }
        return@forEach
      }
    }

    // 转换 SNI 域名
    return hostname?.asciiName
  }

  private fun showTrustedCerts() {
    if (outputCertDetail) {
      for (cert in trustedCerts) {
        println("adding as trusted cert:")
        println("  Subject: " + cert.subjectX500Principal)
        println("  Issuer: " + cert.issuerX500Principal)
        println("  Algorithm: " + cert.publicKey.algorithm)
        println("  Serial number: " + cert.serialNumber.toString(16))
        println("  Valid from " + cert.notBefore + " until " + cert.notAfter)
      }
    }
  }

  private fun showTrustedRootCerts(rootCert: X509Certificate) {
    if (outputCertDetail) {
      println("Found trusted certificate: $rootCert")
    }
  }
}

