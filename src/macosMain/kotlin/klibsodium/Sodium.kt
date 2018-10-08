package klibsodium

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.pin
import kotlinx.cinterop.usePinned
import libsodium.*

@ExperimentalUnsignedTypes
actual object Sodium {
  actual val cryptoKdfKeybytes = crypto_kdf_KEYBYTES
  actual val cryptoShorthashBytes = crypto_shorthash_BYTES.toInt()
  actual val cryptoGenerichashBytes = crypto_generichash_BYTES.toInt()
  actual val cryptoBoxSealbytes = crypto_box_SEALBYTES.toInt()
  actual val cryptoBoxPublickeyBytes = crypto_box_PUBLICKEYBYTES.toInt()
  actual val cryptoBoxSecretkeyBytes = crypto_box_SECRETKEYBYTES.toInt()
  actual val cryptoBoxSeedbytes = crypto_box_SEEDBYTES.toInt()
  actual val cryptoPwhashStrbytes = crypto_pwhash_STRBYTES.toInt()
  actual val cryptoPwhashOpslimitSensitive = crypto_pwhash_OPSLIMIT_SENSITIVE.toInt()
  actual val cryptoPwhashMemlimitSensitive = crypto_pwhash_MEMLIMIT_SENSITIVE.toInt()
  actual val cryptoPwhashOpslimitInteractive = crypto_pwhash_OPSLIMIT_INTERACTIVE.toInt()
  actual val cryptoPwhashMemlimitInteractive = crypto_pwhash_MEMLIMIT_INTERACTIVE.toInt()
  actual val cryptoPwhashAlgDefault = crypto_pwhash_ALG_DEFAULT

  actual fun init(): Boolean {
    return sodium_init() == 0
  }

  actual fun randombytesRandom(): UInt {
    return randombytes_random()
  }

  actual fun randombytesUniform(upperBound: UInt): UInt {
    return randombytes_uniform(upperBound)
  }

  actual fun randombytesBuf(size: ULong): UByteArray {
    val buf = UByteArray(size.toInt()).pin()
    randombytes_buf(
      buf = buf.addressOf(0),
      size = size
    )
    buf.unpin()
    return buf.get()
  }

  actual fun randombytesBufDeterministic(size: ULong, seed: UByteArray): UByteArray {
    val buf = UByteArray(size.toInt()).pin()
    val s = seed.pin()
    randombytes_buf_deterministic(
      buf = buf.addressOf(0),
      size = size,
      seed = s.addressOf(0)
    )
    buf.unpin()
    s.unpin()
    return buf.get()
  }

  actual fun randombytesClose() {
    randombytes_close()
  }

  actual fun bin2hex(bin: UByteArray): ByteArray {
    val maxLen = bin.size * 2 + 1
    val hex = ByteArray(maxLen).pin()
    bin.usePinned { pinned ->
      sodium_bin2hex(
        hex = hex.addressOf(0),
        hex_maxlen = maxLen.toULong(),
        bin = pinned.addressOf(0),
        bin_len = bin.size.toULong()
      )
    }
    hex.unpin()
    return hex.get()
  }

  actual fun cryptoPwhash(password: String, salt: ByteArray, keyLength: Int): UByteArray =
    UByteArray(keyLength).apply {
      val pinnedSalt = salt.asUByteArray().pin()
      val res = usePinned { pinned ->
        crypto_pwhash(
          out = pinned.addressOf(0),
          outlen = crypto_box_SEEDBYTES.toULong(),
          passwd = password,
          passwdlen = password.length.toULong(),
          salt = pinnedSalt.addressOf(0),
          opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE.toULong(),
          memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE.toULong(),
          alg = crypto_pwhash_ALG_DEFAULT
        )
      }
      pinnedSalt.unpin()
      if (res != 0) {
        error("out of memory")
      }
    }

  actual fun cryptoPwhashStr(password: String?): ByteArray {
    val hashedPassword = ByteArray(crypto_pwhash_STRBYTES.toInt()).pin()
    val res = crypto_pwhash_str(
      out = hashedPassword.addressOf(0),
      passwd = password,
      passwdlen = (password?.length ?: 0).toULong(),
      opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE.toULong(),
      memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE.toULong()
    )
    hashedPassword.unpin()
    if (res != 0) {
      error("Password hash failed")
    }
    return hashedPassword.get().run { copyOf(indexOf(0.toByte())) }
  }

  actual fun cryptoPwhashStrVerify(hashedPassword: ByteArray, password: String?): Boolean {
    return hashedPassword.usePinned { pinned ->
      crypto_pwhash_str_verify(
        str = pinned.addressOf(0),
        passwd = password,
        passwdlen = (password?.length ?: 0).toULong()
      )
    } == 0
  }

  actual fun cryptoPwhashStrNeedsRehash(
    hashedPassword: ByteArray,
    opslimit: ULong,
    memlimit: ULong
  ): Boolean {
    return hashedPassword.usePinned { pinned ->
      crypto_pwhash_str_needs_rehash(
        str = pinned.addressOf(0),
        opslimit = opslimit,
        memlimit = memlimit
      )
    } != 0
  }

  actual fun cryptoBoxKeypair(pkLen: Int, skLen: Int): BoxKeyPair {
    val rPK = UByteArray(pkLen).pin()
    val rSK = UByteArray(skLen).pin()
    val res = crypto_box_keypair(rPK.addressOf(0), rSK.addressOf(0))
    rPK.unpin()
    rSK.unpin()
    if (res != 0) {
      error("Failed to create keypair")
    }
    return rPK.get() to rSK.get()
  }

  actual fun cryptoBoxSeal(message: UByteArray, pk: UByteArray): UByteArray {
    val ciphertext = UByteArray(crypto_box_SEALBYTES.toInt() + message.size).pin()
    val pinnedPK = pk.pin()
    val m = message.pin()
    val res = crypto_box_seal(
      c = ciphertext.addressOf(0),
      m = m.addressOf(0),
      mlen = message.size.toULong(),
      pk = pinnedPK.addressOf(0)
    )
    ciphertext.unpin()
    pinnedPK.unpin()
    m.unpin()
    if (res != 0) {
      error("Failed to seal message")
    }
    return ciphertext.get()
  }

  actual fun cryptoBoxOpen(ciphertext: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray {
    val m = UByteArray(ciphertext.size - crypto_box_SEALBYTES.toInt()).pin()
    val c = ciphertext.pin()
    val rPK = pk.pin()
    val rSK = sk.pin()
    val res = crypto_box_seal_open(
      m = m.addressOf(0),
      c = c.addressOf(0),
      clen = ciphertext.size.toULong(),
      pk = rPK.addressOf(0),
      sk = rSK.addressOf(0)
    )
    m.unpin()
    c.unpin()
    rPK.unpin()
    rSK.unpin()
    if (res != 0) {
      error("failed to decrypt message")
    }
    return m.get()
  }

  actual fun cryptoGenerichash(message: UByteArray, key: UByteArray?): UByteArray {
    val hash = UByteArray(crypto_generichash_BYTES.toInt()).pin()
    val m = message.pin()
    val k = key?.pin()
    crypto_generichash(
      out = hash.addressOf(0),
      outlen = crypto_generichash_BYTES.toULong(),
      `in` = m.addressOf(0),
      inlen = message.size.toULong(),
      key = k?.addressOf(0),
      keylen = (key?.size ?: 0).toULong()
    )
    hash.unpin()
    m.unpin()
    k?.unpin()
    return hash.get()
  }

  actual fun cryptoKdfKeygen() =
    UByteArray(crypto_kdf_KEYBYTES).pin()
      .apply {
        crypto_kdf_keygen(addressOf(0))
        unpin()
      }.get()

  actual fun cryptoKdfDeriveFromKey(subKeylen: Int, subkeyId: Int, context: ByteArray, masterkey: UByteArray): UByteArray {
    val subKey = UByteArray(subKeylen).pin()
    val ctx = context.pin()
    val key = masterkey.pin()
    val res = crypto_kdf_derive_from_key(
      subkey = subKey.addressOf(0),
      subkey_len = subKeylen.toULong(),
      subkey_id = subkeyId.toULong(),
      ctx = ctx.addressOf(0),
      key = key.addressOf(0)
    )
    subKey.unpin()
    ctx.unpin()
    key.unpin()
    if (res != 0) {
      error("Failed to derive key")
    }
    return subKey.get()
  }

  actual fun cryptoShorthashKeygen(): UByteArray {
    return UByteArray(crypto_shorthash_KEYBYTES.toInt()).apply {
      usePinned { crypto_shorthash_keygen(it.addressOf(0)) }
    }
  }

  actual fun cryptoShorthash(key: UByteArray, shortData: UByteArray): UByteArray {
    return UByteArray(crypto_shorthash_BYTES.toInt()).apply {
      val k = key.pin()
      val i = shortData.pin()
      val res = usePinned {
        crypto_shorthash(
          out = it.addressOf(0),
          `in` = i.addressOf(0),
          inlen = shortData.size.toULong(),
          k = k.addressOf(0)
        )
      }
      k.unpin()
      i.unpin()
      if (res != 0) {
        error("Shorthash failed")
      }
    }
  }
}
