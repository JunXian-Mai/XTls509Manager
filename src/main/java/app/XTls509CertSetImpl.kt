package app

import org.markensic.xtls.impl.XTls509CertSet


object XTls509CertSetImpl : XTls509CertSet {
  override fun getCaCertPaths(): Array<String> {
    return arrayOf(
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/server.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/test-signing-ca.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/test-root-ca.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/all-ca.crt",
      "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/all-ca-my.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/all-ca-bad-root.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/all-ca-fake-root.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/server-expired.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/test-bad-root-ca.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/test-fake-root-ca.crt",
//    "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/openssl/rootCA.pem",
//  "",
    )
  }

  override fun getClientKeyCertPathPairs(): Array<XTls509CertSet.ClientKeyPem> {
    return arrayOf(
//    ClientKeyPem(
//      "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/client.crt",
//      "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/client-key.pem"
//    ),
      XTls509CertSet.ClientKeyPem(
        "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/clientmy.crt",
        "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/client-key.pem"
      ),
//    ClientKeyPem(
//      "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/client-expired.crt",
//      "/Users/maijunxian/IdeaProjects/XTls509ManagerDemo/certs/testssl/client-key.pem"
//    ),
    )
  }

  override fun getIgnoreTargetIPVerifierList(): Array<String> {
    return arrayOf(
      ""
    )
  }

  override fun getIgnoreTargetHostVerifierList(): Array<String> {
    return arrayOf(
      ""
    )
  }

  override fun getIgnoreAccessIPVerifierList(): Array<String> {
    return arrayOf(
      "127.0.0.1"
    )
  }

  override fun getIgnoreAccessHostVerifierList(): Array<String> {
    return arrayOf(
      "127.0.0.1"
    )
  }
}
