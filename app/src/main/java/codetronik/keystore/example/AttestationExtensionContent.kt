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
import java.security.cert.X509Certificate

class AttestationExtensionContent {
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
		val verifiedBootHash: String?
	)

	fun parseKeyDescription(certificate: X509Certificate): KeyDescription? {
			val extValue = certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") ?: run {
			println("OID not found in the certificate.")
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

		val verifiedBootKey = String((iterator.nextElement() as DEROctetString).octets)
		val deviceLocked = (iterator.nextElement() as ASN1Boolean).isTrue
		val verifiedBootState = decodeVerifiedBootState(iterator.nextElement() as ASN1Enumerated)

		var verifiedBootHash : String? = null
		if (iterator.hasMoreElements()) {
			verifiedBootHash = String((iterator.nextElement() as DEROctetString).octets)
		}

		return RootOfTrust(verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash)
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

	private fun decodeSecurityLevel(securityLevel: ASN1Enumerated): String {
		return when (securityLevel.value.toInt()) {
			0 -> "Software"
			1 -> "TrustedEnvironment"
			2 -> "StrongBox"
			else -> "Unknown"
		}
	}
}