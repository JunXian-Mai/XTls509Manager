package bj.anydef.tls.cert.etc

import com.sun.org.apache.xml.internal.security.utils.Base64
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.*
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object AnydefX509ManagerEtc {

  private val caFactory = CertificateFactory.getInstance("X.509")

  /**
   * 获取Java SDK 中默认的证书信任库，信任的根证列表
   * 获取SDK下指定目录的文件导出信任根证列表
   * @return SDK 信任根证列表
   */
  @Throws(CertificateException::class)
  fun getSystemTrustedCerts(): Array<X509Certificate> {
    val filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar)
    FileInputStream(filename).use {
      val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
      val password = "changeit"
      keystore.load(it, password.toCharArray())
      val params = PKIXParameters(keystore)
      return params.trustAnchors.map { ta ->
        ta.trustedCert
      }.toTypedArray()
    }
  }

  /**
   * 根据信任的证书路径列表获取信任的证书列表
   * @param caCertPath 信任的证书路径列表
   * @return 指定路径下的证书列表
   */
  fun getCaCertificates(caCertPath: Array<String> = AnydefX509Certs.sCaCertPaths): Array<X509Certificate> {
    return caCertPath.map { path ->
      FileInputStream(path).use {
        caFactory.generateCertificate(it) as X509Certificate
      }
    }.toTypedArray()
  }

  /**
   * 根据密钥文件路径，获取密钥文件中的密钥
   * @param certKeyPath 密钥文件路径
   * @return 密钥文件中的密钥
   */
  fun getCertPrivateKey(certKeyPath: String): PrivateKey {
    val keyIns = FileInputStream(certKeyPath)
    val br = BufferedReader(InputStreamReader(keyIns))
    val builder = StringBuilder()
    br.useLines {
      it.forEach { line ->
        if (line[0] != '-') {
          builder.append(line)
          builder.append('\r')
        }
      }
    }
    val buffer = Base64.decode(builder.toString())
    val keySpec = PKCS8EncodedKeySpec(buffer)
    val keyFactory = KeyFactory.getInstance("RSA")
    return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
  }

  /**
   * 根据客户端证书及密钥路径封装类，生成对应密钥的密钥管理器
   * @param keyCertPathPair 客户端证书及密钥路径封装类
   * @param password 密钥密码
   * @return 密钥管理器
   */
  fun getKeyManagerFactory(
    keyCertPathPair: AnydefX509Certs.ClientKeyPem = AnydefX509Certs.sClientKeyCertPathPairs[0],
    password: String = ""
  ): KeyManagerFactory {
    return KeyManagerFactory.getInstance("PKIX").apply {
      val clientCertIns = FileInputStream(keyCertPathPair.cert)
      val clientCert: X509Certificate = caFactory.generateCertificate(clientCertIns) as X509Certificate
      val clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType())
      clientKeyStore.load(null, null)
      clientKeyStore.setCertificateEntry("certificate", clientCert)
      clientKeyStore.setKeyEntry(
        "private-key",
        getCertPrivateKey(keyCertPathPair.key),
        password.toCharArray(),
        arrayOf<Certificate>(clientCert)
      )
      init(clientKeyStore, password.toCharArray())
    }
  }

  /**
   * 获取系统的默认证书信任管理器
   * @return 系统默认证书信任管理器
   */
  @Throws(IllegalStateException::class)
  fun getSystemDefaultTrustManager(): X509TrustManager {
    val tmFactory = TrustManagerFactory.getInstance(
      TrustManagerFactory.getDefaultAlgorithm()
    ).apply {
      init(null as KeyStore?)
    }
    var manager: X509TrustManager? = null
    tmFactory.trustManagers.forEach {
      if (it is X509TrustManager) {
        manager = it
        return@forEach
      }
    }
    return manager
      ?: throw IllegalStateException("Unexpected default trust managers: ${Arrays.toString(tmFactory.trustManagers)}")
  }
}
