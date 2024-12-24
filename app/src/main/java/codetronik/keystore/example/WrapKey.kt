package codetronik.keystore.example

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.WrappedKeyEntry
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class WrapKey {
	private val APP_KEY_ALIAS = "APP_KEY_ALIAS"
	private lateinit var publicKey : java.security.PublicKey
	private lateinit var keystoreSymKey : java.security.Key
	private lateinit var keyStore : java.security.KeyStore
	private lateinit var context : android.content.Context

	fun init(context: Context, alias: String) {
		keyStore = KeyStore.getInstance("AndroidKeyStore")
		keyStore.load(null)
		this.context = context

		getPublicKey()
		getKey(alias)
	}

	private fun isStrongBoxSupported(): Boolean {
		val packageManager = context.packageManager
		return packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
	}

	// 앱에서 한번만 생성
	fun generateAppKeyPair(useStrongBox: Boolean) : PublicKey {
		val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")

		kpg.initialize(
			KeyGenParameterSpec.Builder(APP_KEY_ALIAS, KeyProperties.PURPOSE_WRAP_KEY)
				.setDigests(KeyProperties.DIGEST_SHA256)
				.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
				.setBlockModes(KeyProperties.BLOCK_MODE_ECB)
				.setIsStrongBoxBacked(useStrongBox)
				.build()
		)

		return kpg.generateKeyPair().public
	}

	private fun removeTagType(tag: Int): Int {
		val kmTagTypeMask = 0x0FFFFFFF
		return tag and kmTagTypeMask
	}

	private fun createAuthSequence(): DERSequence {
		val allPurposes = ASN1EncodableVector()
		allPurposes.add(ASN1Integer(KeyMasterDef.KM_PURPOSE_ENCRYPT.value))
		allPurposes.add(ASN1Integer(KeyMasterDef.KM_PURPOSE_DECRYPT.value))

		val purposeSet = DERSet(allPurposes)
		val purpose = DERTaggedObject(true, removeTagType(KeyMasterDef.KM_TAG_PURPOSE.value.toInt()), purposeSet)
		val algorithm = DERTaggedObject(true, removeTagType(KeyMasterDef.KM_TAG_ALGORITHM.value.toInt()), ASN1Integer(KeyMasterDef.KM_ALGORITHM_AES.value))
		val keySize = DERTaggedObject(true, removeTagType(KeyMasterDef.KM_TAG_KEY_SIZE.value.toInt()), ASN1Integer(256))

		// 지원하고자 하는 AES 모드 추가
		val allBlockModes = ASN1EncodableVector()
		allBlockModes.add(ASN1Integer(KeyMasterDef.KM_MODE_GCM.value))

		val blockModeSet = DERSet(allBlockModes)
		val blockMode =	DERTaggedObject(true, removeTagType(KeyMasterDef.KM_TAG_BLOCK_MODE.value.toInt()), blockModeSet)

		// 지원하고자 하는 패딩 추가
		val allPaddings = ASN1EncodableVector()
		allPaddings.add(ASN1Integer(KeyMasterDef.KM_PAD_NONE.value))

		val paddingSet = DERSet(allPaddings)
		val padding = DERTaggedObject(true, removeTagType(KeyMasterDef.KM_TAG_PADDING.value.toInt()), paddingSet)

		val noAuthRequired = DERTaggedObject(true, removeTagType(KeyMasterDef.KM_TAG_NO_AUTH_REQUIRED.value.toInt()), DERNull.INSTANCE)

		// 결합
		val allItems = ASN1EncodableVector()
		allItems.add(purpose);
		allItems.add(algorithm);
		allItems.add(keySize);
		allItems.add(blockMode);
		allItems.add(padding);
		allItems.add(noAuthRequired);

		return DERSequence(allItems)
	}

	private fun createEphemeralKey(): Pair<ByteArray, ByteArray> {
		val random = SecureRandom()

		// 12바이트 AES IV 생성
		val iv = ByteArray(12)
		random.nextBytes(iv)

		// 32바이트 AES 키 생성
		val key = ByteArray(32)
		random.nextBytes(key)

		return key to iv
	}

	private fun wrapKey(key: ByteArray, authorizationList: DERSequence): ByteArray {
		// 공개키로 암호화 세팅
		val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
		val pkCipher = Cipher.getInstance("RSA/ECB/OAEPPadding")

		pkCipher.init(Cipher.ENCRYPT_MODE, publicKey, spec)

		// 임시키 생성
		val (ephemeralKey, ephemeralIv) = createEphemeralKey()
		val encryptedEphemeralKey = pkCipher.doFinal(ephemeralKey)

		// 인자로 받은 키를 공개키 암호화
		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		val secretKeySpec = SecretKeySpec(ephemeralKey, "AES")
		val gcmParameterSpec = GCMParameterSpec(128, ephemeralIv)
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec)

		val descriptionItems = ASN1EncodableVector().apply {
			add(ASN1Integer(KeyMasterDef.KM_KEY_FORMAT_RAW.value))
			add(authorizationList)
		}

		val wrappedKeyDescription = DERSequence(descriptionItems)
		val aad = wrappedKeyDescription.encoded

		cipher.updateAAD(aad)
		var encryptedSecureKey = cipher.doFinal(key)

		val len = encryptedSecureKey.size
		val tagSize = 16
		val tag = Arrays.copyOfRange(encryptedSecureKey, len - tagSize, len)

		// 암호문에서 tag 제거
		encryptedSecureKey = Arrays.copyOfRange(encryptedSecureKey, 0, len - tagSize)

		val items = ASN1EncodableVector().apply {
			add(ASN1Integer(3))
			add(DEROctetString(encryptedEphemeralKey))
			add(DEROctetString(ephemeralIv))
			add(wrappedKeyDescription)
			add(DEROctetString(encryptedSecureKey))
			add(DEROctetString(tag))
		}

		println(DERSequence(items).encoded.joinToString("") { String.format("%02X", it) })

		return DERSequence(items).encoded
	}

	private fun getKey(alias: String) {
		if(keyStore.containsAlias(alias)) {
			keystoreSymKey = keyStore.getKey(alias, null)
		} else {
			val kg = KeyGenerator.getInstance("AES")
			kg.init(256)
			importKey(alias, kg.generateKey().encoded)
		}
	}

	private fun importKey(alias: String, key: ByteArray) {
		val spec = KeyGenParameterSpec.Builder(APP_KEY_ALIAS, KeyProperties.PURPOSE_WRAP_KEY)
					.setDigests(KeyProperties.DIGEST_SHA256)
					.build()

		val wrappedKey = wrapKey(key, createAuthSequence())
		val wrappedKeyEntry = WrappedKeyEntry(wrappedKey, APP_KEY_ALIAS, "RSA/ECB/OAEPPadding", spec)

		keyStore.setEntry(alias, wrappedKeyEntry, null)
		keystoreSymKey = keyStore.getKey(alias, null)
	}

	private fun getPublicKey() {
		if(false == keyStore.containsAlias(APP_KEY_ALIAS)) {
			// 키가 없으면 만듦
			publicKey = generateAppKeyPair(isStrongBoxSupported())
		} else {
			// 키가 있으면 가져옴
			val entry = keyStore.getEntry(APP_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
			publicKey = entry.certificate.publicKey
		}
	}

	fun encrypt(data: ByteArray, aad: ByteArray) : Pair<ByteArray, ByteArray> {
		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		cipher.init(Cipher.ENCRYPT_MODE, keystoreSymKey)
		cipher.updateAAD(aad)

		return cipher.doFinal(data) to cipher.iv
	}

	fun decrypt(encryptedData: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray {
		val cipher = Cipher.getInstance("AES/GCM/NoPadding")
		cipher.init(Cipher.DECRYPT_MODE, keystoreSymKey, GCMParameterSpec(128, iv)) // 128은 태그 길이 (비트 단위)
		cipher.updateAAD(aad)

		return cipher.doFinal(encryptedData)
	}
}