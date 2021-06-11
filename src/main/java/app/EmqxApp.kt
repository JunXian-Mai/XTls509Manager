package app

import org.eclipse.paho.client.mqttv3.*
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import org.markensic.xtls.XTlsKeyManagerBuilder
import org.markensic.xtls.XTlsTrustManagerBuilder
import org.markensic.xtls.etc.Source
import org.markensic.xtls.hostname.XTlsHostVerifier
import java.security.SecureRandom
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory


class EmqxApp {

  companion object {

    val hostname = XTlsHostVerifier(XTls509CertSetImpl)

    val trustBuilder = XTlsTrustManagerBuilder(Source.PATH())

    val keyBuilder = XTlsKeyManagerBuilder(Source.PATH())

    val pushCallBack = PushCallBack()

    /**
     * mutual
     *   false 单向验证
     *   true 双向验证
     */
    fun getSSLSocketFactory(mutual: Boolean = false): SSLSocketFactory {
      val trustManager = trustBuilder
        .addPath("/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/all-ca-my.crt")
        .attachSystemCerts(true)
        .build(hostname)
//      val trustManager = TrustAllManager()  //不验证证书
      var keyManager: KeyManagerFactory? = null
      if (mutual) {
        //客户端密钥
        keyManager = keyBuilder
          .addClientKeyPath(
            "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/clientmy.crt",
            "/Users/maijunxian/IdeaProjects/Paho_Java/certs/testssl/client-key.pem")
          .build()
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
        connOpts.sslHostnameVerifier = XTlsHostVerifier(XTls509CertSetImpl)
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


