package bj.anydef.tls.cert.etc

object AnydefX509Certs {
  val sCaCertPaths = arrayOf(
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/server.crt", //服务器证书
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-signing-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-root-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca.crt", //完整的根证
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-my.crt", //完整的根证
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-bad-root.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-fake-root.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/server-expired.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-bad-root-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/test-fake-root-ca.crt", //
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/openssl/rootCA.pem", //另一个自签根证
  )

  val sServerCertPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/server.crt"
  )

  val sClientCertPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/clientmy.crt"
  )

  val sClientKeyPaths = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem"
  )

  val sClientKeyCertPathPairs = arrayOf(
    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem"
      to "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/clientmy.crt",
//    "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem"
//      to "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-expired.crt",
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

  val sIgnoreHostVerifierList =
    sIgnoreTargetIPVerifierList.plus(sIgnoreTargetHostVerifierList).plus(sIgnoreAccessIPVerifierList).plus(sIgnoreAccessHostVerifierList)
}
