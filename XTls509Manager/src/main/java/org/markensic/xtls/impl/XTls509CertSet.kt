package org.markensic.xtls.impl

interface XTls509CertSet {
  fun getCaCertPaths(): Array<String>

  fun getClientKeyCertPathPairs(): Array<ClientKeyPem>

  fun getIgnoreTargetIPVerifierList(): Array<String>

  fun getIgnoreTargetHostVerifierList(): Array<String>

  fun getIgnoreAccessIPVerifierList(): Array<String>

  fun getIgnoreAccessHostVerifierList(): Array<String>

  class ClientKeyPem(val cert: String, val key: String)
}
