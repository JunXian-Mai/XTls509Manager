package org.markensic.xtls.hostname

interface XTlsHostnameConfig {
  fun getIgnoreTargetIPVerifierList(): Array<String>

  fun getIgnoreTargetHostVerifierList(): Array<String>

  fun getIgnoreAccessIPVerifierList(): Array<String>

  fun getIgnoreAccessHostVerifierList(): Array<String>
}
