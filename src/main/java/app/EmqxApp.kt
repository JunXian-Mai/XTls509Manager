package app

import bj.anydef.tls.cert.etc.AnydefX509ManagerEtc
import bj.anydef.tls.cert.manager.AnydefHostnameVerifier
import bj.anydef.tls.cert.manager.AnydefX509TrustManager
import org.eclipse.paho.client.mqttv3.*
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager


class EmqxApp {

  companion object {
    val pushCallBack = PushCallBack()

    /**
     * mutual
     *   false 单向验证
     *   true 双向验证
     */
    fun getSSLSocketFactory(mutual: Boolean = false): SSLSocketFactory {
      val trustManager = AnydefX509TrustManager()  //自定义证书信任器
//      val trustManager = TrustAllManager()  //不验证证书
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        //客户端密钥
        keyManager = AnydefX509ManagerEtc.getKeyManagerFactory()
      }

      val context = SSLContext.getInstance("TLSv1.2")
      context.init(
        if (mutual) keyManager?.keyManagers else null,
        arrayOf(trustManager),
        SecureRandom()
      )
      return context.socketFactory
    }

    @JvmStatic
    fun main(args: Array<String>) {
      val subTopic = "testtopic/#"
      val pubTopic = "testtopic/1"
      val content = "Hello World"
      val qos = 2
      val broker = "ssl://127.0.0.1:8883"
      val clientId = "java_emqx_test"
      val persistence = MemoryPersistence()

      try {
        //建立客户端
        val client = MqttClient(broker, clientId, persistence)

        //连接选项
        val connOpts = MqttConnectOptions()
        connOpts.userName = "java_emqx_test"
        connOpts.password = "java_emqx_test".toCharArray()
        //会话保留
        connOpts.isCleanSession = true
        //设置证书验证
        connOpts.socketFactory = getSSLSocketFactory(true)
        connOpts.sslHostnameVerifier = AnydefHostnameVerifier
        //设置回调
        client.setCallback(pushCallBack)
        //建立连接
        println("Connecting to broker: $broker")
        client.connect(connOpts)

        println(
          """
          Connected
          Publishing message: $content
        """.trimIndent()
        )

        //订阅
        client.subscribe(subTopic)

        val message = MqttMessage(content.toByteArray())
        message.qos = qos
        //发布订阅
        client.publish(pubTopic, message)
        println("Message published")

//        client.disconnect()
//        println("Disconnected")
//        client.close()
//        exitProcess(0)
      } catch (e: MqttException) {
        println(
          """
          reason: ${e.reasonCode}
          msg: ${e.message}
          loc: ${e.localizedMessage}
          cause: ${e.cause}
          excep: $e
        """.trimIndent()
        )
      }
    }
  }

  class PushCallBack : MqttCallback {
    override fun connectionLost(p0: Throwable) {
      println("连接已经断开，重连......")
    }

    override fun messageArrived(topic: String, message: MqttMessage) {
      println(
        """
        接收到的消息主题: $topic
        接收到的消息Qos: ${message.qos}
        接收到的消息内容： ${String(message.payload)}
      """.trimIndent()
      )
    }

    override fun deliveryComplete(token: IMqttDeliveryToken) {
      println("deliveryComplete---------${token.isComplete}")
    }
  }
}

class TrustAllManager() : X509TrustManager {
  private val issuers: Array<X509Certificate> = arrayOf()

  override fun getAcceptedIssuers(): Array<X509Certificate> {
    return issuers
  }

  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String?) {}

  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?) {}
}
