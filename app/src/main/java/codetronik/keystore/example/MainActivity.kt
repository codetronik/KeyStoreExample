package codetronik.keystore.example

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

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

		wrapKeyTest("key1_alias")
		wrapKeyTest("key2_alias")
		certTest()
	}

	fun certTest() {
		// 서버에서 챌린지 받아옴
		val srv = VerifyServer()
		val challenge = srv.createChallenge(5)

		val keyAttestation = KeyAttestation()
		keyAttestation.init(this)

		// 서버에서 받아온 챌린지 설정
		keyAttestation.generateSignKeyPair(challenge.encodeToByteArray())
		var certChain = keyAttestation.getCertificateChain()

		// 서버에서 인증서 검증
		if(!srv.verifyCertChain(certChain)) {
			println("Certificate verification failure")
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