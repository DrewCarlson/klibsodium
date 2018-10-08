package klibsodium

import org.libsodium.jni.Sodium as JNISodium
import org.libsodium.jni.NaCl


@ExperimentalUnsignedTypes
actual object Sodium {

  actual fun init(): Boolean {
    NaCl.sodium()
    return JNISodium.sodium_init() == 0
  }

  actual fun randombytesRandom(): UInt {
    return JNISodium.randombytes_random().toUInt()
  }

  actual fun randombytesUniform(upperBound: UInt): UInt {
    return JNISodium.randombytes_uniform(upperBound.toInt()).toUInt()
  }

  actual fun randombytesBuf(size: ULong): UByteArray {
    val buf = ByteArray(size.toInt())
    JNISodium.randombytes_buf(buf, buf.size)
    return buf.asUByteArray()
  }

  actual fun randombytesBufDeterministic(size: ULong, seed: UByteArray): UByteArray {
    TODO("Not implemented by JNISodium")
  }

  actual fun randombytesClose() {
    JNISodium.randombytes_close()
  }

  actual fun bin2hex(bin: UByteArray): ByteArray {
    TODO("not implemented")
  }

  actual fun cryptoPwhash(password: String, salt: ByteArray, keyLength: Int): UByteArray {
    val buf = ByteArray(keyLength)
    JNISodium.crypto_pwhash(buf,
      keyLength,
      password.toByteArray(),
      password.length,
      salt,
      JNISodium.crypto_pwhash_opslimit_sensitive(),
      JNISodium.crypto_pwhash_memlimit_sensitive(),
      JNISodium.crypto_pwhash_alg_default()
    )
    return buf.asUByteArray()
  }

  actual fun cryptoPwhashStr(password: String?): ByteArray {
    val buf = ByteArray(JNISodium.crypto_pwhash_strbytes())
    JNISodium.crypto_pwhash_str(
      buf,
      password?.toByteArray(),
      password?.length ?: 0,
      JNISodium.crypto_pwhash_opslimit_sensitive(),
      JNISodium.crypto_pwhash_memlimit_sensitive())
    return buf
  }

  actual fun cryptoPwhashStrVerify(hashedPassword: ByteArray, password: String?): Boolean {
    return JNISodium.crypto_pwhash_str_verify(hashedPassword, password?.toByteArray(), password?.length ?: 0) == 0
  }

  actual fun cryptoPwhashStrNeedsRehash(
    hashedPassword: ByteArray,
    opslimit: ULong,// = crypto_pwhash_OPSLIMIT_SENSITIVE.toULong(),
    memlimit: ULong// = crypto_pwhash_MEMLIMIT_SENSITIVE.toULong()
  ): Boolean {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoBoxKeypair(
    pkLen: Int,// = crypto_box_PUBLICKEYBYTES.toInt(),
    skLen: Int// = crypto_box_SECRETKEYBYTES.toInt()
  ): BoxKeyPair {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoBoxSeal(message: UByteArray, pk: UByteArray): UByteArray {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoBoxOpen(ciphertext: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoGenerichash(message: UByteArray, key: UByteArray?): UByteArray {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoKdfKeygen(): UByteArray {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoKdfDeriveFromKey(
    subKeylen: Int,
    subkeyId: Int,
    context: ByteArray,
    masterkey: UByteArray
  ): UByteArray {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoShorthashKeygen(): UByteArray {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
  }

  actual fun cryptoShorthash(key: UByteArray, shortData: UByteArray): UByteArray {
    val out = ByteArray(JNISodium.crypto_shorthash_bytes())
    JNISodium.crypto_shorthash(out, shortData.asByteArray(), shortData.size, key.asByteArray())
    return out.asUByteArray()
  }
}
