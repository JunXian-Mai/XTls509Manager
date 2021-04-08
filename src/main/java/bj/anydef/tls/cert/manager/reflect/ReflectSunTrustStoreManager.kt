package bj.anydef.tls.cert.manager.reflect

import java.security.cert.X509Certificate

internal class ReflectSunTrustStoreManager {
  fun getTrustedCerts(): Array<X509Certificate> {
    val trustStoreManagerClazz = Class.forName("sun.security.ssl.TrustStoreManager")
    val getTrustedCerts = trustStoreManagerClazz.getDeclaredMethod("getTrustedCerts")
    getTrustedCerts.isAccessible = true
    return (getTrustedCerts.invoke(null) as Set<X509Certificate>).toTypedArray()
  }
}
