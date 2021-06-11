package org.markensic.xtls.etc

sealed class Source private constructor() {
  class NONE : Source()
  class PATH: Source()
  class CONTENT: Source()
}
