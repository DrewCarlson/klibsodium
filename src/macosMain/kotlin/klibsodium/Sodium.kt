package klibsodium

import kotlinx.cinterop.*

actual fun sodium_init(): Boolean {
  return libsodium.sodium_init() == 0
}

actual fun randombytes_random(): UInt {
  return libsodium.randombytes_random()
}

actual fun randombytes_uniform(upperBound: UInt): UInt {
  return libsodium.randombytes_uniform(upperBound)
}

actual fun randombytes_buf(size: ULong): UByteArray {
  return UByteArray(size.toInt()).usePinned { buf ->
    libsodium.randombytes_buf(
      buf = buf.addressOf(0),
      size = size
    )
    buf.get()
  }
}

actual fun randombytes_buf_deterministic(size: ULong, seed: UByteArray): UByteArray {
  return UByteArray(size.toInt()).usePinned { buf ->
    val s = seed.pin()
    libsodium.randombytes_buf_deterministic(
      buf = buf.addressOf(0),
      size = size,
      seed = s.addressOf(0)
    )
    s.unpin()
    buf.get()
  }
}

actual fun randombytes_close() {
  libsodium.randombytes_close()
}

actual fun sodium_bin2hex(bin: UByteArray): ByteArray {
  val maxLen = bin.size * 2 + 1
  return ByteArray(maxLen).usePinned { hex ->
    val input = bin.pin()
    libsodium.sodium_bin2hex(
      hex = hex.addressOf(0),
      hex_maxlen = maxLen.toULong(),
      bin = input.addressOf(0),
      bin_len = bin.size.toULong()
    )
    input.unpin()
    hex.get()
  }
}

actual fun crypto_pwhash(password: String, salt: ByteArray, keyLength: Int): UByteArray =
  UByteArray(keyLength).apply {
    val pinnedSalt = salt.asUByteArray().pin()
    val res = usePinned { pinned ->
      libsodium.crypto_pwhash(
        out = pinned.addressOf(0),
        outlen = libsodium.crypto_box_SEEDBYTES.toULong(),
        passwd = password,
        passwdlen = password.length.toULong(),
        salt = pinnedSalt.addressOf(0),
        opslimit = libsodium.crypto_pwhash_OPSLIMIT_INTERACTIVE.toULong(),
        memlimit = libsodium.crypto_pwhash_MEMLIMIT_INTERACTIVE.toULong(),
        alg = libsodium.crypto_pwhash_ALG_DEFAULT
      )
    }
    pinnedSalt.unpin()
    if (res != 0) {
      error("out of memory")
    }
  }

actual fun crypto_pwhash_str(password: String?): ByteArray {
  val hashedPassword = ByteArray(libsodium.crypto_pwhash_STRBYTES.toInt()).pin()
  val res = libsodium.crypto_pwhash_str(
    out = hashedPassword.addressOf(0),
    passwd = password,
    passwdlen = (password?.length ?: 0).toULong(),
    opslimit = libsodium.crypto_pwhash_OPSLIMIT_SENSITIVE.toULong(),
    memlimit = libsodium.crypto_pwhash_MEMLIMIT_SENSITIVE.toULong()
  )
  hashedPassword.unpin()
  if (res != 0) {
    error("Password hash failed")
  }
  return hashedPassword.get().run { copyOf(indexOf(0.toByte())) }
}

actual fun crypto_pwhash_str_verify(hashedPassword: ByteArray, password: String?): Boolean {
  return hashedPassword.usePinned { pinned ->
    libsodium.crypto_pwhash_str_verify(
      str = pinned.addressOf(0),
      passwd = password,
      passwdlen = (password?.length ?: 0).toULong()
    )
  } == 0
}

actual fun crypto_pwhash_str_needs_rehash(
  hashedPassword: ByteArray,
  opslimit: ULong,
  memlimit: ULong
): Boolean {
  return hashedPassword.usePinned { pinned ->
    libsodium.crypto_pwhash_str_needs_rehash(
      str = pinned.addressOf(0),
      opslimit = opslimit,
      memlimit = memlimit
    )
  } != 0
}

actual fun crypto_box_keypair(pkLen: Int, skLen: Int): BoxKeyPair {
  val rPK = UByteArray(pkLen).pin()
  val rSK = UByteArray(skLen).pin()
  val res = libsodium.crypto_box_keypair(rPK.addressOf(0), rSK.addressOf(0))
  rPK.unpin()
  rSK.unpin()
  if (res != 0) {
    error("Failed to create keypair")
  }
  return rPK.get() to rSK.get()
}

actual fun crypto_box_seal(message: UByteArray, pk: UByteArray): UByteArray {
  val ciphertext = UByteArray(libsodium.crypto_box_SEALBYTES.toInt() + message.size).pin()
  val pinnedPK = pk.pin()
  val m = message.pin()
  val res = libsodium.crypto_box_seal(
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

actual fun crypto_box_open(ciphertext: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray {
  val m = UByteArray(ciphertext.size - libsodium.crypto_box_SEALBYTES.toInt()).pin()
  val c = ciphertext.pin()
  val rPK = pk.pin()
  val rSK = sk.pin()
  val res = libsodium.crypto_box_seal_open(
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

actual fun crypto_generichash(message: UByteArray, key: UByteArray?): UByteArray {
  return UByteArray(libsodium.crypto_generichash_BYTES.toInt()).usePinned { hash ->
    val m = message.pin()
    val k = key?.pin()
    libsodium.crypto_generichash(
      out = hash.addressOf(0),
      outlen = libsodium.crypto_generichash_BYTES.toULong(),
      `in` = m.addressOf(0),
      inlen = message.size.toULong(),
      key = k?.addressOf(0),
      keylen = (key?.size ?: 0).toULong()
    )
    m.unpin()
    k?.unpin()
    hash.get()
  }
}

actual fun crypto_kdf_keygen() =
  UByteArray(libsodium.crypto_kdf_KEYBYTES).pin()
    .apply {
      libsodium.crypto_kdf_keygen(addressOf(0))
      unpin()
    }.get()

actual fun crypto_kdf_derive_from_key(
  subKeylen: Int,
  subkeyId: Int,
  context: ByteArray,
  masterkey: UByteArray
): UByteArray {
  val subKey = UByteArray(subKeylen).pin()
  val ctx = context.pin()
  val key = masterkey.pin()
  val res = libsodium.crypto_kdf_derive_from_key(
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

actual fun crypto_shorthash_keygen(): UByteArray {
  return UByteArray(libsodium.crypto_shorthash_KEYBYTES.toInt()).apply {
    usePinned { libsodium.crypto_shorthash_keygen(it.addressOf(0)) }
  }
}

actual fun crypto_shorthash(key: UByteArray, shortData: UByteArray): UByteArray {
  return UByteArray(libsodium.crypto_shorthash_BYTES.toInt()).apply {
    val k = key.pin()
    val i = shortData.pin()
    val res = usePinned { out ->
      libsodium.crypto_shorthash(
        out = out.addressOf(0),
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

actual fun crypto_sign_keypair(): SignKeyPair {
  val pk = UByteArray(libsodium.crypto_sign_PUBLICKEYBYTES.toInt()).pin()
  val sk = UByteArray(libsodium.crypto_sign_SECRETKEYBYTES.toInt()).pin()
  val res = libsodium.crypto_sign_keypair(pk.addressOf(0), sk.addressOf(0))
  pk.unpin()
  sk.unpin()
  if (res != 0) {
    error("Failed to create sign keypair")
  }
  return pk.get() to sk.get()
}

actual fun crypto_sign(message: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray {
  val out = UByteArray(libsodium.crypto_sign_BYTES.toInt() + message.size).pin()
  val m = message.pin()
  val s = sk.pin()
  memScoped {
    val smlemP = alloc<ULongVar>()
    libsodium.crypto_sign(
      sm = out.addressOf(0),
      smlen_p = smlemP.ptr,
      m = m.addressOf(0),
      mlen = message.size.toULong(),
      sk = s.addressOf(0)
      )
  }
  out.unpin()
  s.unpin()
  m.unpin()
  return out.get()
}
