package bj.anydef.tls.cert.etc

import com.sun.org.apache.xml.internal.security.utils.Base64
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object AnydefX509ManagerEtc {
  private val caFactory = CertificateFactory.getInstance("X.509")

  private enum class Type {
    CA_TYPE,
    CLIENT_TYPE,
    SERVER_TYPE
  }

  var sAttachSystemCert = true

  var sPrintLnCerts = false

  fun getCaCertificates(): Array<X509Certificate> {
    return getCertificates(Type.CA_TYPE)
  }

  fun getClientCertificates(): Array<X509Certificate> {
    return getCertificates(Type.CLIENT_TYPE)
  }

  fun getServerCertificates(): Array<X509Certificate> {
    return getCertificates(Type.SERVER_TYPE)
  }

  fun getCertificates(certPaths: Array<String>): Array<X509Certificate> {
    return certPaths.map {
      val caIns = FileInputStream(it)
      caFactory.generateCertificate(caIns) as X509Certificate
    }.toTypedArray()
  }

  private fun getCertificates(type: Type): Array<X509Certificate> {
    return when (type) {
      Type.CA_TYPE -> AnydefX509Certs.sCaCertPaths
      Type.CLIENT_TYPE -> AnydefX509Certs.sClientCertPaths
      Type.SERVER_TYPE -> AnydefX509Certs.sServerCertPaths
    }.map {
      val caIns = FileInputStream(it)
      caFactory.generateCertificate(caIns) as X509Certificate
    }.toTypedArray()
  }

  fun getCertPrivateKey(certKeyPath: String = AnydefX509Certs.sClientKeyPaths[0]): PrivateKey {
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

  fun getKeyManagerFactory(keyCertPathPair: Pair<String, String> = AnydefX509Certs.sClientKeyCertPathPairs[0], password: String = ""): KeyManagerFactory {
    return KeyManagerFactory.getInstance("PKIX").apply {
      val clientCertIns = FileInputStream(keyCertPathPair.second)
      val clientCert: X509Certificate = caFactory.generateCertificate(clientCertIns) as X509Certificate
      val clientKeyStore = KeyStore.getInstance("JKS")
      clientKeyStore.load(null, null)
      clientKeyStore.setCertificateEntry("certificate", clientCert)
      clientKeyStore.setKeyEntry("private-key", getCertPrivateKey(keyCertPathPair.first), password.toCharArray(), arrayOf<Certificate>(clientCert))
      init(clientKeyStore, "".toCharArray())
    }
  }

  @Throws(IllegalStateException::class)
  fun getSystemDefaultTrustManager(): X509TrustManager {
    val tmFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
      init(null as KeyStore?)
    }
    var manager: X509TrustManager? = null
    tmFactory.trustManagers.forEach {
      if (it is X509TrustManager) {
        manager = it
        return@forEach
      }
    }
    return manager ?: throw IllegalStateException("Unexpected default trust managers: ${Arrays.toString(tmFactory.trustManagers)}")
  }
}
