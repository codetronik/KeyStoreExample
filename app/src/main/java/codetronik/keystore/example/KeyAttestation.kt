package codetronik.keystore.example

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore


class KeyAttestation {
	private val SIGN_KEY_ALIAS = "SIGN_KEY_ALIAS"

	private lateinit var keyStore : java.security.KeyStore
	private lateinit var context : android.content.Context

	private fun isStrongBoxSupported(): Boolean {
		val packageManager = context.packageManager
		return packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
	}

	fun init(context: Context) {
		keyStore = KeyStore.getInstance("AndroidKeyStore")
		keyStore.load(null)
		this.context = context
	}

	fun generateSignKeyPair(challenge: ByteArray) {
		val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

		kpg.initialize(
			KeyGenParameterSpec.Builder(SIGN_KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
				.setAttestationChallenge(challenge)
				.setIsStrongBoxBacked(isStrongBoxSupported())
				.build()
		)

		var keyPair = kpg.generateKeyPair()
	}

	fun getCertificateChain() : ByteArray {
		val certificateChain = keyStore.getCertificateChain(SIGN_KEY_ALIAS)

		// 인증서 체인을 하나의 ByteArray로 합침
		return certificateChain.flatMap { certificate ->
			certificate.encoded.toList()
		}.toByteArray()
	}
}