package org.markensic.xtls.etc

sealed class Source private constructor() {
  class PATH: Source()
  class CONTENT: Source()
}
