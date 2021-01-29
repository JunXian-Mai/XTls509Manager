package app

import app.EmqxApp.Companion.gmCaPath
import app.EmqxApp.Companion.gmClientKeyPath
import bj.anydef.tls.cert.etc.AnydefX509ManagerEtc
import bj.anydef.tls.cert.manager.AnydefX509TrustManager
import cn.gmssl.jce.provider.GMJCE
import cn.gmssl.jsse.provider.GMJSSE
import com.sun.org.apache.xml.internal.security.utils.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.paho.client.mqttv3.*
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.*


class EmqxApp {

  companion object {
    val pushCallBack = PushCallBack()

    val gmCaPath = "/Users/maijunxian/IdeaProjects/Paho_Java/certs/gmssl/rootCA.pem"
    val gmClientPath = "/Users/maijunxian/IdeaProjects/Paho_Java/certs/gmssl/client.pem"
    val gmClientKeyPath = "/Users/maijunxian/IdeaProjects/Paho_Java/certs/gmssl/client-key.pem"

    fun getSSLSocketFactory(mutual: Boolean = false): SSLSocketFactory {
      val trustManager = AnydefX509TrustManager()
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        keyManager = AnydefX509ManagerEtc.getKeyManagerFactory()
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(if (mutual) keyManager?.keyManagers else null, arrayOf(trustManager), SecureRandom())
      return context.socketFactory
    }

    @JvmStatic
    fun main(args: Array<String>) {
      val subTopic = "testtopic/#"
      val pubTopic = "testtopic/1"
      val content = "Hello World"
      val qos = 2
      val broker = "ssl://localhost:8883"
      val clientId = "java_emqx_test"
      val persistence = MemoryPersistence()

      try {
        val client = MqttClient(broker, clientId, persistence)

        //连接选项
        val connOpts = MqttConnectOptions()
        connOpts.userName = "java_emqx_test"
        connOpts.password = "java_emqx_test".toCharArray()
        //会话保留
        connOpts.isCleanSession = true
        connOpts.socketFactory = getSSLSocketFactory(true)

        //设置回调
        client.setCallback(pushCallBack)

        //建立连接
        println("Connecting to broker: $broker")
        client.connect(connOpts)

        println("""
          Connected
          Publishing message: $content
        """.trimIndent())

        //订阅
        client.subscribe(subTopic)

        val message = MqttMessage(content.toByteArray())
        message.qos = qos
        client.publish(pubTopic, message)
        println("Message published")

//        client.disconnect()
//        println("Disconnected")
//        client.close()
//        exitProcess(0)
      } catch (e: MqttException) {
        println("""
          reason: ${e.reasonCode}
          msg: ${e.message}
          loc: ${e.localizedMessage}
          cause: ${e.cause}
          excep: $e
        """.trimIndent())
      }
    }
  }

  class PushCallBack : MqttCallback {
    override fun connectionLost(p0: Throwable) {
      println("连接已经断开，重连......")
    }

    override fun messageArrived(topic: String, message: MqttMessage) {
      println("""
        接收到的消息主题: $topic
        接收到的消息Qos: ${message.qos}
        接收到的消息内容： ${String(message.payload)}
      """.trimIndent())
    }

    override fun deliveryComplete(token: IMqttDeliveryToken) {
      println("deliveryComplete---------${token.isComplete}")
    }
  }
}

fun getGMSSLSocketFactory(mutual: Boolean = false): SSLSocketFactory {
  val protocol = GMJSSE.GMSSLv11
  val provider = GMJSSE.NAME
  Security.insertProviderAt(GMJCE(), 1)
  Security.insertProviderAt(GMJSSE(), 2)

  Security.addProvider(BouncyCastleProvider())
  val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

  val caIns = FileInputStream(gmCaPath)
  val cf = CertificateFactory.getInstance("X.509", "BC")
  val ca = cf.generateCertificate(caIns) as X509Certificate
  val caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType())
  caKeyStore.load(null, null);
  caKeyStore.setCertificateEntry("ca-certificate", ca);
  tmf.init(caKeyStore)

  val trusts = arrayOf(TrustAllManager())
  val context = SSLContext.getInstance(protocol, provider)
  context.init(null, trusts, SecureRandom())

  return context.socketFactory
}

fun getGMPrivateKey(): PrivateKey {
  val keyIns = FileInputStream(gmClientKeyPath)
  val br = BufferedReader(InputStreamReader(keyIns))
  val builder = StringBuilder()
  br.useLines {
    it.forEach { line ->
      if (line[0] != '-') {
        builder.append(line)
        builder.append('\r')
      }
    }
  }
  val buffer = Base64.decode(builder.toString())
  val keySpec = PKCS8EncodedKeySpec(buffer)
  val keyFactory = KeyFactory.getInstance("RSA")
  return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
}

class TrustAllManager(cert: X509Certificate? = null) : X509TrustManager {
  private val issuers: Array<X509Certificate> = if (cert == null) {
    arrayOf()
  } else {
    arrayOf(cert)
  }

  override fun getAcceptedIssuers(): Array<X509Certificate> {
    return issuers
  }
  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String?) {}
  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?) {}
}
