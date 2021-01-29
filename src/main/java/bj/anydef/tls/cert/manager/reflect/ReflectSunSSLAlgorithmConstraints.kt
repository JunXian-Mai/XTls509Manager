package bj.anydef.tls.cert.manager.reflect

import java.security.AlgorithmConstraints
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket

internal class ReflectSunSSLAlgorithmConstraints {
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
