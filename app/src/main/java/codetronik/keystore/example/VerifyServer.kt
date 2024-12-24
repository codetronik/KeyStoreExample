package codetronik.keystore.example

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

data class KeyDescription(
	val attestationVersion: Int,
	val attestationSecurityLevel: String,
	val keymasterVersion: Int,
	val keymasterSecurityLevel: String,
	val attestationChallenge: String,
	val uniqueId: String,
	val softwareEnforced: AuthorizationList,
	val teeEnforced: AuthorizationList
)

data class AuthorizationList(
	val purpose: List<Int>?,
	val algorithm: Int?,
	val keySize: Int?,
	val digest: List<Int>?,
	val padding: List<Int>?,
	val ecCurve: Int?,
	val rsaPublicExponent: Long?,
	val rollbackResistance: Boolean?,
	val earlyBootOnly: Boolean?,
	val activeDateTime: Long?,
	val originationExpireDateTime: Long?,
	val usageExpireDateTime: Long?,
	val noAuthRequired: Boolean?,
	val userAuthType: Int?,
	val authTimeout: Int?,
	val allowWhileOnBody: Boolean?,
	val trustedUserPresenceRequired: Boolean?,
	val trustedConfirmationRequired: Boolean?,
	val unlockedDeviceRequired: Boolean?,
	val allApplications: Boolean?,
	val applicationId: String?,
	val creationDateTime: Long?,
	val origin: Int?,
	val rootOfTrust: RootOfTrust?,
	val osVersion: Int?,
	val osPatchLevel: Int?,
	val attestationApplicationId: String?,
	val vendorPatchLevel: Int?,
	val bootPatchLevel: Int?,
	val deviceUniqueAttestation: Boolean?
)

data class RootOfTrust(
	val verifiedBootKey: String,
	val deviceLocked: Boolean,
	val verifiedBootState: String,
	val verifiedBootHash: String
)

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

	fun verifyCertChain(certChain: ByteArray) : Boolean {
		val certificateFactory = CertificateFactory.getInstance("X.509")
		val certList = mutableListOf<X509Certificate>()
		val inputStream = ByteArrayInputStream(certChain)
		while (inputStream.available() > 0) {
			val certificate = certificateFactory.generateCertificate(inputStream) as X509Certificate
			certList.add(certificate)
		}

		// 인증서 출력
		certList.forEachIndexed { index, cert ->
			println("Certificate [$index]:")
			println("Subject: ${cert.subjectDN}")
			println("Issuer: ${cert.issuerDN}")
			println("Serial Number: ${cert.serialNumber}")
			println("Valid From: ${cert.notBefore}")
			println("Valid To: ${cert.notAfter}")
			println("--------------------------------------------------")
		}

		// 인증서에서 KeyDescription 파싱
		val keyDescription = parseAttestationExtensionContent(certList.first())
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

	fun parseAttestationExtensionContent(cert: X509Certificate): KeyDescription? {
		val oid = "1.3.6.1.4.1.11129.2.1.17"
		val extValue = cert.getExtensionValue(oid) ?: run {
			println("OID $oid not found in the certificate.")
			return null
		}

		val asn1InputStream = ASN1InputStream(ByteArrayInputStream(extValue))
		val derObject = asn1InputStream.readObject()
		asn1InputStream.close()

		val octetInputStream = ASN1InputStream(ByteArrayInputStream((derObject as DEROctetString).octets))
		val asn1Sequence = octetInputStream.readObject() as ASN1Sequence
		octetInputStream.close()

		val elements = asn1Sequence.objects.toList() // Enumeration -> List 변환
		return KeyDescription(
			attestationVersion = (elements[0] as ASN1Integer).value.toInt(),
			attestationSecurityLevel = decodeSecurityLevel(elements[1] as ASN1Enumerated),
			keymasterVersion = (elements[2] as ASN1Integer).value.toInt(),
			keymasterSecurityLevel = decodeSecurityLevel(elements[3] as ASN1Enumerated),
			attestationChallenge = String((elements[4] as DEROctetString).octets),
			uniqueId = String((elements[5] as DEROctetString).octets),
			softwareEnforced = parseAuthorizationList(elements[6] as ASN1Sequence),
			teeEnforced = parseAuthorizationList(elements[7] as ASN1Sequence)
		)
	}

	private fun decodeSecurityLevel(securityLevel: ASN1Enumerated): String {
		return when (securityLevel.value.toInt()) {
			0 -> "Software"
			1 -> "TrustedEnvironment"
			2 -> "StrongBox"
			else -> "Unknown"
		}
	}

	private fun parseAuthorizationList(sequence: ASN1Sequence): AuthorizationList {
		val map = mutableMapOf<Int, Any?>()
		val iterator = sequence.objects
		while (iterator.hasMoreElements()) {
			val taggedObject = iterator.nextElement() as ASN1TaggedObject
			map[taggedObject.tagNo] = taggedObject.`object`
		}

		return AuthorizationList(
			purpose = (map[1] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() },
			algorithm = (map[2] as? ASN1Integer)?.value?.toInt(),
			keySize = (map[3] as? ASN1Integer)?.value?.toInt(),
			digest = (map[5] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() },
			padding = (map[6] as? ASN1Set)?.objects?.toList()?.map { (it as ASN1Integer).value.toInt() },
			ecCurve = (map[10] as? ASN1Integer)?.value?.toInt(),
			rsaPublicExponent = (map[200] as? ASN1Integer)?.value?.toLong(),
			rollbackResistance = map[303] is ASN1Null,
			earlyBootOnly = map[305] is ASN1Null,
			activeDateTime = (map[400] as? ASN1Integer)?.value?.toLong(),
			originationExpireDateTime = (map[401] as? ASN1Integer)?.value?.toLong(),
			usageExpireDateTime = (map[402] as? ASN1Integer)?.value?.toLong(),
			noAuthRequired = map[503] is ASN1Null,
			userAuthType = (map[504] as? ASN1Integer)?.value?.toInt(),
			authTimeout = (map[505] as? ASN1Integer)?.value?.toInt(),
			allowWhileOnBody = map[506] is ASN1Null,
			trustedUserPresenceRequired = map[507] is ASN1Null,
			trustedConfirmationRequired = map[508] is ASN1Null,
			unlockedDeviceRequired = map[509] is ASN1Null,
			allApplications = map[600] is ASN1Null,
			applicationId = (map[601] as? DEROctetString)?.octets?.let { String(it) },
			creationDateTime = (map[701] as? ASN1Integer)?.value?.toLong(),
			origin = (map[702] as? ASN1Integer)?.value?.toInt(),
			rootOfTrust = (map[704] as? ASN1Sequence)?.let { parseRootOfTrust(it) },
			osVersion = (map[705] as? ASN1Integer)?.value?.toInt(),
			osPatchLevel = (map[706] as? ASN1Integer)?.value?.toInt(),
			attestationApplicationId = (map[709] as? DEROctetString)?.octets?.let { String(it) },
			vendorPatchLevel = (map[718] as? ASN1Integer)?.value?.toInt(),
			bootPatchLevel = (map[719] as? ASN1Integer)?.value?.toInt(),
			deviceUniqueAttestation = map[720] is ASN1Null
		)
	}

	private fun parseRootOfTrust(sequence: ASN1Sequence): RootOfTrust {
		val iterator = sequence.objects
		return RootOfTrust(
			verifiedBootKey = String((iterator.nextElement() as DEROctetString).octets),
			deviceLocked = (iterator.nextElement() as ASN1Boolean).isTrue,
			verifiedBootState = decodeVerifiedBootState(iterator.nextElement() as ASN1Enumerated),
			verifiedBootHash = String((iterator.nextElement() as DEROctetString).octets)
		)
	}

	private fun decodeVerifiedBootState(verifiedBootState: ASN1Enumerated): String {
		return when (verifiedBootState.value.toInt()) {
			0 -> "Verified"
			1 -> "SelfSigned"
			2 -> "Unverified"
			3 -> "Failed"
			else -> "Unknown"
		}
	}
}