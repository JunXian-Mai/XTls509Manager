package bj.anydef.tls.cert.etc

object AnydefX509Certs {
  val sCaCertPaths = arrayOf(
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/server.crt", //服务器证书
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-signing-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-root-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca.crt", //完整的根证
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-my.crt", //完整的根证
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-bad-root.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-fake-root.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/server-expired.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-bad-root-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-fake-root-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/rootCA.pem", //另一个自签根证
//  "",
  )

  val sClientKeyCertPathPairs = arrayOf(
//    ClientKeyPem(
//      "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client.crt",
//      "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem"
//    ),
    ClientKeyPem(
      "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/clientmy.crt",
      "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem"
    ),
//    ClientKeyPem(
//      "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-expired.crt",
//      "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem"
//    ),
  )

  val sIgnoreTargetIPVerifierList = arrayOf(
    ""
  )

  val sIgnoreTargetHostVerifierList = arrayOf(
    ""
  )

  val sIgnoreAccessIPVerifierList = arrayOf(
    "127.0.0.1"
  )

  val sIgnoreAccessHostVerifierList = arrayOf(
    "localhost"
  )

  class ClientKeyPem(val cert: String, val key: String)
}
