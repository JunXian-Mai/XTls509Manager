package bj.anydef.tls.cert.manager.reflect

import sun.security.ssl.ProtocolVersion

internal class ReflectSunProtocolVersion {
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
