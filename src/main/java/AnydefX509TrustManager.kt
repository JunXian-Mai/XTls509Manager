import sun.security.ssl.ProtocolVersion
import sun.security.util.HostnameChecker
import sun.security.validator.Validator
import java.io.FileInputStream
import java.net.Socket
import java.security.AlgorithmConstraints
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.*

class AnydefX509TrustManager(
  private val validatorType: String = Validator.TYPE_PKIX,
  trustedCerts: Array<X509Certificate> = AnydefX509Manager.getCaCertificates(),
  attachSystemCerts: Boolean = true
) : X509ExtendedTrustManager() {

  private val protocol = ReflectSunProtocolVersion()

  private val sslAlgorithmConstraints = ReflectSunSSLAlgorithmConstraints()

  private val trustedCerts: Array<X509Certificate>

  private val isPrintLog = false

  @Volatile
  private var clientValidator: Validator? = null

  @Volatile
  private var serverValidator: Validator? = null

  init {
    AnydefX509Manager.sAttachSystemCert = attachSystemCerts
    if (AnydefX509Manager.sAttachSystemCert) {
      val trustStoreManagerClazz = Class.forName("sun.security.ssl.TrustStoreManager")
      val getTrustedCerts = trustStoreManagerClazz.getDeclaredMethod("getTrustedCerts")
      getTrustedCerts.isAccessible = true
      val certs: Set<X509Certificate> = getTrustedCerts.invoke(null) as Set<X509Certificate>
      this.trustedCerts = certs.toTypedArray().plus(trustedCerts)
    } else {
      this.trustedCerts = trustedCerts
    }

    if (AnydefX509Manager.sPrintLnCerts) {
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

  private fun checkTrustedInit(chain: Array<out X509Certificate>?,
                               authType: String?, checkClientTrusted: Boolean): Validator {
    if (chain == null || chain.isEmpty()) {
      throw java.lang.IllegalArgumentException("null or zero-length certificate chain")
    }

    if (authType.isNullOrBlank()) {
      throw java.lang.IllegalArgumentException("null or zero-length authentication type")
    }

    var v: Validator?
    if (checkClientTrusted) {
      v = clientValidator
      if (v == null) {
        synchronized(this) {
          v = clientValidator
          if (v == null) {
            v = getValidator(Validator.VAR_TLS_CLIENT)
            clientValidator = v
          }
        }
      }
    } else {
      v = serverValidator
      if (v == null) {
        synchronized(this) {
          v = serverValidator
          if (v == null) {
            v = getValidator(Validator.VAR_TLS_SERVER)
            serverValidator = v
          }
        }
      }
    }
    return v!!
  }

  @Throws(CertificateException::class)
  private fun checkTrusted(chain: Array<out X509Certificate>?,
                           authType: String?, socket: Socket?,
                           checkClientTrusted: Boolean) {
    val v = checkTrustedInit(chain, authType, checkClientTrusted)

    var constraints: AlgorithmConstraints? = null
    if (socket is SSLSocket && socket.isConnected) {
      val session = socket.handshakeSession
        ?: throw CertificateException("No handshake session")

      val identityAlg = socket.sslParameters.endpointIdentificationAlgorithm
      if (identityAlg?.isNotBlank() == true) {
        checkIdentity(session, chain!!, identityAlg, checkClientTrusted)
      }

      val protocolVersion: ProtocolVersion = protocol.valueOf(session.protocol)
      if (protocolVersion.v >= protocol.getProtocolVersionInStatic("TLS12").v) {
        if (session is ExtendedSSLSession) {
          val localSupportedSignAlgs = session.localSupportedSignatureAlgorithms
          constraints = sslAlgorithmConstraints.newInstance(
            socket, localSupportedSignAlgs, false)
        } else {
          constraints = sslAlgorithmConstraints.newInstance(socket, withDefaultCertPathConstraints = false)
        }
      } else {
        constraints = sslAlgorithmConstraints.newInstance(socket, withDefaultCertPathConstraints = false)
      }
    }

    var trustedChain: Array<out X509Certificate>?
    trustedChain = if (checkClientTrusted) {
      validate(v, chain!!, constraints, null)
    } else {
      validate(v, chain!!, constraints, authType)
    }
    showTrustedRootCerts(trustedChain[trustedChain.size - 1])
  }

  @Throws(CertificateException::class)
  private fun checkTrusted(chain: Array<out X509Certificate>?,
                           authType: String?, engine: SSLEngine?,
                           checkClientTrusted: Boolean) {
    val v = checkTrustedInit(chain, authType, checkClientTrusted)

    var constraints: AlgorithmConstraints? = null
    if (engine != null) {
      val session = engine.handshakeSession
        ?: throw CertificateException("No handshake session")

      val identityAlg = engine.sslParameters.endpointIdentificationAlgorithm
      if (identityAlg?.isNotBlank() == true) {
        checkIdentity(session, chain!!, identityAlg, checkClientTrusted)
      }

      val protocolVersion: ProtocolVersion = protocol.valueOf(session.protocol)
      if (protocolVersion.v >= protocol.getProtocolVersionInStatic("TLS12").v) {
        if (session is ExtendedSSLSession) {
          val localSupportedSignAlgs = session.localSupportedSignatureAlgorithms
          constraints = sslAlgorithmConstraints.newInstance(
            engine, localSupportedSignAlgs, false)
        } else {
          constraints = sslAlgorithmConstraints.newInstance(engine, withDefaultCertPathConstraints = false)
        }
      } else {
        constraints = sslAlgorithmConstraints.newInstance(engine, withDefaultCertPathConstraints = false)
      }
    }

    var trustedChain: Array<out X509Certificate>?
    trustedChain = if (checkClientTrusted) {
      validate(v, chain!!, constraints, null)
    } else {
      validate(v, chain!!, constraints, authType)
    }
    showTrustedRootCerts(trustedChain[trustedChain.size - 1])
  }

  private fun getValidator(variant: String): Validator =
    Validator.getInstance(validatorType, variant, trustedCerts.toMutableSet())

  @Throws(CertificateException::class)
  private fun validate(v: Validator,
                       chain: Array<out X509Certificate>, constraints: AlgorithmConstraints?,
                       authType: String?): Array<X509Certificate> {
    return v.validate(chain, null, constraints, authType)
  }

  private fun getHostNameInSNI(sniNames: List<SNIServerName>): String {
    var hostname: SNIHostName? = null
    sniNames.forEach {
      if (it.type == StandardConstants.SNI_HOST_NAME) {
        if (it is SNIHostName) {
          hostname = it
        } else {
          try {
            hostname = SNIHostName(it.encoded)
          } catch (iae: IllegalArgumentException) {
            printlog("Illegal server name: $it")
          }
        }
        return@forEach
      }
    }

    return hostname?.asciiName ?: ""
  }

  fun getRequestedServerNames(socket: Socket?): List<SNIServerName> {
    return if (socket is SSLSocket && socket.isConnected) {
      getRequestedServerNames(socket.handshakeSession)
    } else emptyList()
  }

  fun getRequestedServerNames(engine: SSLEngine?): List<SNIServerName> {
    return if (engine != null) {
      getRequestedServerNames(engine.handshakeSession)
    } else emptyList()
  }

  private fun getRequestedServerNames(session: SSLSession?): List<SNIServerName> {
    return if (session is ExtendedSSLSession) {
      session.requestedServerNames
    } else emptyList()
  }

  @Throws(CertificateException::class)
  fun checkIdentity(session: SSLSession,
                    trustedChain: Array<out X509Certificate>,
                    algorithm: String,
                    checkClientTrusted: Boolean) {
    var identifiable = false
    val peerHost = session.peerHost
    if (!checkClientTrusted) {
      val sniNames = getRequestedServerNames(session)
      val sniHostName = getHostNameInSNI(sniNames)
      try {
        checkIdentity(sniHostName, trustedChain[0], algorithm)
        identifiable = true
      } catch (ce: CertificateException) {
        if (sniHostName.equals(peerHost, ignoreCase = true)) {
          throw ce
        }
      }
    }

    if (!identifiable) {
      checkIdentity(peerHost, trustedChain[0], algorithm)
    }
  }

  @Throws(CertificateException::class)
  fun checkIdentity(hostname: String?,
                    cert: X509Certificate,
                    algorithm: String?) {
    var hn = hostname ?: String()
    if (algorithm?.isNotBlank() == true) {
      if (hn.startsWith("[") && hn.endsWith("]")) {
        hn = hn.substring(1, hn.length - 1)
      }
      if (algorithm.equals("HTTPS", ignoreCase = true)) {
        HostnameChecker.getInstance(HostnameChecker.TYPE_TLS).match(
          hn, cert)
      } else if (algorithm.equals("LDAP", ignoreCase = true) ||
        algorithm.equals("LDAPS", ignoreCase = true)) {
        HostnameChecker.getInstance(HostnameChecker.TYPE_LDAP).match(
          hn, cert)
      } else {
        throw CertificateException(
          "Unknown identification algorithm: $algorithm")
      }
    }
  }

  private fun showTrustedCerts() {
    if (isPrintLog) {
      for (cert in trustedCerts) {
        printlog("""
          adding as trusted cert:
            Subject: ${cert.subjectX500Principal}
            Issuer: ${cert.issuerX500Principal}
            Algorithm: ${cert.publicKey.algorithm}
            Serial number: ${cert.serialNumber.toString(16)}
            Valid from ${cert.notBefore} until ${cert.notAfter}
        """.trimIndent())
      }
    }
  }

  private fun showTrustedRootCerts(rootCert: X509Certificate) {
    if (isPrintLog) {
      printlog("""
        Found trusted certificate: ${rootCert}
      """.trimIndent())
    }
  }

  object AnydefX509Manager {
    private val caFactory = CertificateFactory.getInstance("X.509")

    private val caCertPaths = arrayOf(
      "/Users/maijunxian/IdeaProjects/Paho Java/certs/openssl/rootCA.pem",
    )

    private val serverCertPaths = arrayOf(
      "/Users/maijunxian/IdeaProjects/Paho Java/certs/openssl/server.pem"
    )

    private val clientCertPaths = arrayOf(
      "/Users/maijunxian/IdeaProjects/Paho Java/certs/openssl/client.pem"
    )

    enum class Type {
      CA_TYPE,
      CLIENT_TYPE,
      SERVER_TYPE
    }

    var sAttachSystemCert = true

    var sPrintLnCerts = true

    fun getCaCertificates(): Array<X509Certificate> {
      return getCertificates(Type.CA_TYPE)
    }

    fun getClientCertificates(): Array<X509Certificate> {
      return getCertificates(Type.CLIENT_TYPE)
    }

    fun getServerCertificates(): Array<X509Certificate> {
      return getCertificates(Type.SERVER_TYPE)
    }

    private fun getCertificates(type: Type): Array<X509Certificate> {
      return when (type) {
        Type.CA_TYPE -> caCertPaths
        Type.CLIENT_TYPE -> clientCertPaths
        Type.SERVER_TYPE -> serverCertPaths
      }.map {
        val caIns = FileInputStream(it)
        caFactory.generateCertificate(caIns) as X509Certificate
      }.toTypedArray()
    }
  }


  private class ReflectSunProtocolVersion {
    fun valueOf(name: String): ProtocolVersion {
      val clazz = Class.forName("sun.security.ssl.ProtocolVersion")
      val method = clazz.getDeclaredMethod("valueOf", String::class.java)
      method.isAccessible = true
      return method.invoke(null, name) as ProtocolVersion
    }

    fun getProtocolVersionInStatic(propertyName: String): ProtocolVersion {
      val clazz = Class.forName("sun.security.ssl.ProtocolVersion")
      val field = clazz.getDeclaredField(propertyName)
      field.isAccessible = true
      return field.get(null) as ProtocolVersion
    }
  }

  private class ReflectSunSSLAlgorithmConstraints {
    fun newInstance(
      socket: SSLSocket,
      supportedAlgorithms: Array<String>? = null,
      withDefaultCertPathConstraints: Boolean): AlgorithmConstraints {

      val clazz = Class.forName("sun.security.ssl.SSLAlgorithmConstraints")
      val constructor = if (supportedAlgorithms != null) {
        clazz.getDeclaredConstructor(SSLSocket::class.java, Array<String>::class.java, Boolean::class.java)
      } else {
        clazz.getDeclaredConstructor(SSLSocket::class.java, Boolean::class.java)
      }
      constructor.isAccessible = true
      return if (supportedAlgorithms != null) {
        constructor.newInstance(socket, supportedAlgorithms, withDefaultCertPathConstraints) as AlgorithmConstraints
      } else {
        constructor.newInstance(socket, withDefaultCertPathConstraints) as AlgorithmConstraints
      }
    }

    fun newInstance(
      engine: SSLEngine,
      supportedAlgorithms: Array<String>? = null,
      withDefaultCertPathConstraints: Boolean): AlgorithmConstraints {

      val clazz = Class.forName("sun.security.ssl.SSLAlgorithmConstraints")
      val constructor = if (supportedAlgorithms != null) {
        clazz.getDeclaredConstructor(SSLEngine::class.java, Array<String>::class.java, Boolean::class.java)
      } else {
        clazz.getDeclaredConstructor(SSLEngine::class.java, Boolean::class.java)
      }
      constructor.isAccessible = true
      return if (supportedAlgorithms != null) {
        constructor.newInstance(engine, supportedAlgorithms, withDefaultCertPathConstraints) as AlgorithmConstraints
      } else {
        constructor.newInstance(engine, withDefaultCertPathConstraints) as AlgorithmConstraints
      }
    }
  }
}

