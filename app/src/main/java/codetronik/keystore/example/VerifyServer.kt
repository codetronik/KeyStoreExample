package codetronik.keystore.example

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class VerifyServer {
	private lateinit var challenge : String

	fun getGoogleRootPublicKey() : PublicKey {
		val encoded = Base64.getDecoder().decode("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==")
		val keySpec = X509EncodedKeySpec(encoded)
		val keyFactory = KeyFactory.getInstance("RSA")

		return keyFactory.generatePublic(keySpec)
	}

	fun	createChallenge(length : Int) : String {
		require(length in 1..10) { "Length must be between 1 and 10 bytes." }
		val charset = ('a'..'z') + ('A'..'Z') + ('0'..'9')
		challenge = (1..length)
			.map { charset.random() }
			.joinToString("")

		return challenge
	}

	fun isTrustedDevice(certificate: X509Certificate) : Boolean {
		// 인증서에서 KeyDescription 파싱
		var aec = AttestationExtensionContent()

		val keyDescription = aec.parseKeyDescription(certificate)
		if (keyDescription == null) {
			return false
		}

		println("State : " + keyDescription.teeEnforced.rootOfTrust?.verifiedBootState + " / " + keyDescription.teeEnforced.rootOfTrust?.deviceLocked)

		// 루팅 디바이스 체크
		if (keyDescription.teeEnforced.rootOfTrust?.verifiedBootState == "Unverified") {
			return false
		}

		if (keyDescription.teeEnforced.rootOfTrust?.deviceLocked == false) {
			return false
		}

		return true
	}

	fun convertCertChain(certChain: ByteArray) : MutableList<X509Certificate> {
		val certificateFactory = CertificateFactory.getInstance("X.509")
		val certList = mutableListOf<X509Certificate>()
		val inputStream = ByteArrayInputStream(certChain)
		while (inputStream.available() > 0) {
			val certificate = certificateFactory.generateCertificate(inputStream) as X509Certificate
			certList.add(certificate)
		}

		return certList
	}

	fun verifyCertChain(certList: MutableList<X509Certificate>) : Boolean {
		// 인증서에서 KeyDescription 파싱
		var aec = AttestationExtensionContent()

		val keyDescription = aec.parseKeyDescription(certList.first())
		if (keyDescription == null) {
			return false
		}
		if (challenge != keyDescription.attestationChallenge) {
			println("Challenge does not match.")
			return false
		}

		// 루트 인증서 검증
		val rootCertificate = certList.last()
		try {
			rootCertificate.verify(getGoogleRootPublicKey())
		} catch (e: Exception) {
			println("Failed to verify root certificate: ${e.message}")
			return false
		}

		// 밑에서 위로 체인 검증
		for (i in certList.size - 2 downTo 0) {
			val currentCert = certList[i]
			val issuerCert = certList[i + 1]
			try {
				// 현재 인증서의 서명을 상위 인증서의 공개 키로 검증
				currentCert.verify(issuerCert.publicKey)
			} catch (e: Exception) {
				println("Failed to verify certificate at index $i: ${e.message}")
				return false
			}
		}

		return true
	}
}