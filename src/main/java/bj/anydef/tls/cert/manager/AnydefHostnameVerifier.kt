package bj.anydef.tls.cert.manager

import bj.anydef.tls.cert.etc.AnydefX509Certs
import java.security.cert.X509Certificate
import java.util.*
import java.util.regex.Pattern
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession

object AnydefHostnameVerifier : HostnameVerifier {
  private const val ALT_DNS_NAME = 2
  private const val ALT_IPA_NAME = 7

  /**
   * 根据session获取证书，校验证书与域名的一致性
   * @param hostname 访问的host
   * @param session sslsession
   * @return
   */
  override fun verify(host: String, session: SSLSession): Boolean {
    return try {
      verify(host, session.peerCertificates[0] as X509Certificate)
    } catch (_: SSLPeerUnverifiedException) {
      false
    }
  }

  /**
   * 验证访问的host是否匹配证书域名
   * 根据正则表达式判断访问的host是ip地址还是普通域名，2者使用不同的过滤列表进行校验
   * @param host 访问的host
   * @param certificate 证书文件
   * @return 域名校验结果
   */
  fun verify(host: String, certificate: X509Certificate): Boolean {
    // ip地址正则
    val VERIFY_AS_IP_ADDRESS = Pattern.compile("([0-9a-fA-F]*:[0-9a-fA-F:.]*)|([\\d.]+)")
    return if (VERIFY_AS_IP_ADDRESS.matcher(host).matches()) {
      // 获取证书主题中 IP地址
      // 将证书主题中 IP地址，过滤列表中 IP地址进行组合
      val allSubjectNames = getSubjectNames(certificate, ALT_IPA_NAME)
        .plus(AnydefX509Certs.sIgnoreTargetIPVerifierList)
        .plus(AnydefX509Certs.sIgnoreAccessIPVerifierList)
      // 对所有合法的IP地址进行匹配验证
      for (subjectName in allSubjectNames) {
        // 通配符匹配算法
        if (isWildcardsMatch(host, subjectName)) {
          return true
        }
      }
      false
    } else {
      // 获取证书主题中域名地址
      // 将证书主题中域名地址，过滤列表中域名地址进行组合
      // 对所有合法的域名地址进行匹配验证
      val allSubjectNames = getSubjectNames(certificate, ALT_DNS_NAME)
        .plus(AnydefX509Certs.sIgnoreTargetHostVerifierList)
        .plus(AnydefX509Certs.sIgnoreAccessHostVerifierList)
      for (subjectName in allSubjectNames) {
        // 通配符匹配算法
        if (isWildcardsMatch(host, subjectName)) {
          return true
        }
      }
      false
    }
  }

  /**
   * 获取证书主题中域名与主题别名中域名
   * @param certificate 证书
   * @param type 证书主题别名类型
   * @return
   */
  private fun getSubjectNames(certificate: X509Certificate, type: Int): MutableList<String> {
    val names = mutableListOf<String>()
    val dn = certificate.subjectDN
    val subject = dn.name
    subject.split(",").forEach {
      if (it.startsWith("CN=")) {
        names.add(it.replace("CN=", ""))
        return@forEach
      }
    }

    val altNames = certificate.subjectAlternativeNames
    altNames?.forEach { aN ->
      if (aN != null && aN.size >= 2) {
        val t = aN[0] as Int
        if (t == type) {
          val sn = aN[1] as String
          if (!names.contains(sn)) {
            names.add(sn)
          }
        }
      }
    }
    return names
  }

  /**
   * 通配符匹配算法
   * @param origin 需匹配串
   * @param wildcards 通配符表达式
   * @return
   */
  fun isWildcardsMatch(origin: String, wildcards: String): Boolean {
    // i 用来记录origin串检测的索引的位置
    var i = 0
    // j 用来记录wildcards串检测的索引的位置
    var j = 0
    // 记录 待测串i的回溯点
    var ii = -1
    // 记录 通配符*的回溯点
    var jj = -1

    // 以origin符串的长度为循环基数，用i来记录origin串当前的位置
    while (i < origin.length) {
      // 用j来记录wildcards串的当前位置，检测wildcards串中j位置的值是不是通配符*
      if (j < wildcards.length && wildcards[j] == '*') {
        // 如果在wildcards串中碰到通配符*，复制两串的当前索引，记录当前的位置，并对wildcards串+1，定位到非通配符位置
        ii = i
        jj = j
        j++
      } else if (j < wildcards.length // 检测wildcards串是否结束
        && (origin[i] == wildcards[j] // 检测两串当前位置的值是否相等
          || wildcards[j] == '?')
      ) { // 检测wildcards串中j位置是否是单值通配符？
        // 如果此时wildcards串还在有效位置上，那么两串当前位置相等或者wildcards串中是单值通配符，表明此时匹配通过，两串均向前移动一步
        i++
        j++
      } else {
        // 如果在以上两种情况下均放行，表明此次匹配是失败的，那么此时就要明确一点，origin串是否在被wildcards串中的通配符*监听着，
        // 因为在首次判断中如果碰到通配符*，我们会将他当前索引的位置记录在jj的位置上，
        // 如果jj = -1 表明匹配失败，当前origin串不在监听位置上
        if (jj == -1) {
          return false
        }
        // 如果此时在origin串在通配符*的监听下， 让wildcards串回到通配符*的位置上继续监听下一个字符
        j = jj
        // 让i回到origin串中与通配符对应的当前字符的下一个字符上，也就是此轮匹配只放行一个字符
        i = ii + 1
      }
    }

    // 当origin串中的每一个字符都与wildcards串中的字符进行匹配之后，对wildcards串的残余串进行检查，如果残余串是一个*那么继续检测，否则跳出
    while (j < wildcards.length && wildcards[j] == '*') j++

    // 此时查看wildcards是否已经检测到最后，如果检测到最后表示匹配成功，否则匹配失败
    return j == wildcards.length
  }
}
