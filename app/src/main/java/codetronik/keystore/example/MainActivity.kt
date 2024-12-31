package codetronik.keystore.example

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {
	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		enableEdgeToEdge()
		setContentView(R.layout.activity_main)

		ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
			val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
			v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
			insets
		}

		//wrapKeyTest("key1_alias")
		//wrapKeyTest("key2_alias")
		certTest()
	}

	@OptIn(DelicateCoroutinesApi::class)
	fun certTest() {
		val keyAttestation = KeyAttestation()
		keyAttestation.init(this)

		GlobalScope.launch(Dispatchers.IO) {
			val challenge = httpRequest( "http://10.90.226.104:8080/getChallange", null, "GET")
			if (challenge == null) {
				println("Failed to get a response.")
				return@launch // 스코프 밖으로 이동
			}
			println("Response from server: $challenge")

			// 서버에서 받아온 챌린지 설정
			keyAttestation.generateSignKeyPair(challenge.encodeToByteArray())

			val certChain = keyAttestation.getCertificateChain()

			val response = httpRequest( "http://10.90.226.104:8080/sendCertChain", """{"certChain": "$certChain"}""", "POST")
			if (response == null) {
				println("Failed to get a response.")
			}

			launch(Dispatchers.Main) {
				// IO 스레드 실행 후 처리 코드
			}
		}
	}

	fun httpRequest(url: String, json: String?, method: String): String? {
		val requestBody: RequestBody? = json?.toRequestBody("application/json; charset=utf-8".toMediaType())
		val requestBuilder = Request.Builder().url(url)

		if (method == "POST") {
			requestBuilder.post(requestBody!!)
		} else if (method == "GET") {
			requestBuilder.get()
		}

		val request = requestBuilder.build()
		val client = OkHttpClient.Builder()
			.connectTimeout(30, TimeUnit.SECONDS)
			.readTimeout(60, TimeUnit.SECONDS)
			.writeTimeout(60, TimeUnit.SECONDS)
			.build()

		try {
			val response = client.newCall(request).execute()

			if (response.isSuccessful) {
				return response.body?.string()
			} else {
				println("Request failed with status code: ${response.code}")
				return null
			}
		} catch (e: Exception) {
			println("Request failed: ${e.message}")
			return null
		}
	}

	fun wrapKeyTest(alias: String) {
		val wrapKey = WrapKey()
		wrapKey.init(this, alias)

		val data: ByteArray = "hello".toByteArray()
		val aad: ByteArray = "user id".toByteArray()

		val (encryptedData, iv) = wrapKey.encrypt(data, aad)
		val decryptedData = wrapKey.decrypt(encryptedData, iv, aad)
	}
}