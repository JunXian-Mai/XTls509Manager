package bj.anydef.tls.cert.etc

object AnydefX509Certs {
  val sCaCertPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/rootCA.pem",
  )

  val sServerCertPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/server.pem"
  )

  val sClientCertPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/client.pem"
  )

  val sClientKeyPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/client-key.pem"
  )

  val sClientKeyCertPathPairs = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/client-key.pem"
      to "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/client.pem"
  )

  val sIgnoreHostIPVeriferList = arrayOf(
    "127.0.0.1"
  )

  val sIgnoreHostVeriferList = arrayOf(
    ""
  )
}
