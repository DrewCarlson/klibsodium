package demo

import kotlinx.cinterop.*
import libsodium.*

typealias BoxKeyPair = Pair<UByteArray, UByteArray>

object Sodium {
    fun randomSalt(length: Int) =
        UByteArray(length).apply {
            usePinned { pinned ->
                randombytes_buf(pinned.addressOf(0), length.toULong())
            }
        }

    fun randombytesRandom(): UInt {
        return randombytes_random()
    }

    fun randombytesUniform(upperBound: UInt): UInt {
        return randombytes_uniform(upperBound)
    }

    fun randombytesBuf(size: ULong): UByteArray {
        val buf = UByteArray(size.toInt()).pin()
        randombytes_buf(
            buf = buf.addressOf(0),
            size = size
        )
        buf.unpin()
        return buf.get()
    }

    fun randombytesBufDeterministic(size: ULong, seed: UByteArray): UByteArray {
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

    fun randombytesClose() {
        randombytes_close()
    }

    fun bin2hex(bin: UByteArray): ByteArray {
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

    fun cryptoPwhash(password: String, salt: ByteArray, keyLength: Int) =
        UByteArray(keyLength).run {
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
            asByteArray()
        }

    fun cryptoPwhashStr(password: String? = null): ByteArray {
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
        return hashedPassword.get()
    }

    fun cryptoPwhashStrVerify(hashedPassword: ByteArray, password: String? = null): Boolean {
        return hashedPassword.usePinned { pinned ->
            crypto_pwhash_str_verify(
                str = pinned.addressOf(0),
                passwd = password,
                passwdlen = (password?.length ?: 0).toULong()
            )
        } == 0
    }

    fun cryptoPwhashStrNeedsRehash(
        hashedPassword: ByteArray,
        opslimit: ULong = crypto_pwhash_OPSLIMIT_SENSITIVE.toULong(),
        memlimit: ULong = crypto_pwhash_MEMLIMIT_SENSITIVE.toULong()
    ): Boolean {
        return hashedPassword.usePinned { pinned ->
            crypto_pwhash_str_needs_rehash(
                str = pinned.addressOf(0),
                opslimit = opslimit,
                memlimit = memlimit
            )
        } != 0
    }

    fun cryptoBoxKeypair(
        pkLen: Int = crypto_box_PUBLICKEYBYTES.toInt(),
        skLen: Int = crypto_box_SECRETKEYBYTES.toInt()
    ): BoxKeyPair {
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

    fun cryptoBoxSeal(message: UByteArray, pk: UByteArray): UByteArray {
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

    fun cryptoBoxOpen(ciphertext: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray {
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

    fun cryptoGenerichash(message: UByteArray, key: UByteArray? = null): UByteArray {
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

    fun cryptoKdfKeygen() =
        UByteArray(crypto_kdf_KEYBYTES).pin()
            .apply {
                crypto_kdf_keygen(addressOf(0))
                unpin()
            }.get()

    fun cryptoKdfDeriveFromKey(subKeylen: Int, subkeyId: Int, context: ByteArray, masterkey: UByteArray): UByteArray {
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

    fun cryptoShorthashKeygen(): UByteArray {
        return UByteArray(crypto_shorthash_KEYBYTES.toInt()).apply {
            usePinned { crypto_shorthash_keygen(it.addressOf(0)) }
        }
    }

    fun cryptoShorthash(key: UByteArray, shortData: UByteArray): UByteArray {
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

fun main(args: Array<String>) {
    if (sodium_init() == -1) {
        error("sodium_init() failed.")
    }

    /*
    Shorthashing
    https://download.libsodium.org/doc/hashing/short-input_hashing
    val key = Sodium.cryptoShorthashKeygen()
    val hash = Sodium.cryptoShorthash(key, "data".asUByteArray())

    println(hash.asString())
    */

    /* KDF
    https://download.libsodium.org/doc/key_derivation
    val context = "Examples" // Must be 8 characters
    val masterkey = Sodium.cryptoKdfKeygen()
    println("Masterkey: ${masterkey.asString()}")

    val subkey1 = Sodium.cryptoKdfDeriveFromKey(32, 1, context.toUtf8(), masterkey)
    val subkey2 = Sodium.cryptoKdfDeriveFromKey(32, 2, context.toUtf8(), masterkey)
    val subkey3 = Sodium.cryptoKdfDeriveFromKey(64, 3, context.toUtf8(), masterkey)

    println("subkey1: ${subkey1.asString()}")
    println("subkey2: ${subkey2.asString()}")
    println("subkey3: ${subkey3.asString()}")
    */

    /* Generic hash, single-part, no key
    val message = "Message"
    val hash = Sodium.cryptoGenerichash(message.asUByteArray())
    println(hash.asString())
    */

    /* Generic hash, single-part, with key
    val message = "Message"
    val key = Sodium.randomSalt(crypto_generichash_KEYBYTES.toInt())
    val hash = Sodium.cryptoGenerichash(message.asUByteArray(), key)
    println(hash.asString())
    */

    /* Generic hash, multi-part, with key
    val message1 = "message1"
    val message2 = "2"

    val hash = UByteArray(crypto_generichash_BYTES.toInt())
    val key = Sodium.randomSalt(crypto_generichash_KEYBYTES.toInt())

    val state = sodium_malloc(crypto_generichash_statebytes())!!.reinterpret<crypto_generichash_state>()
    val pKey = key.pin()
    val initRes = crypto_generichash_init(
        state = state,
        key = pKey.addressOf(0),
        keylen = key.size.toULong(),
        outlen = hash.size.toULong()
    )
    if (initRes != 0) {
        error("Failed to init hash")
    }

    val m1 = message1.asUByteArray().pin()
    val m2 = message2.asUByteArray().pin()
    val updateRes1 = crypto_generichash_update(state, m1.addressOf(0), message1.length.toULong())
    if (updateRes1 != 0) {
        m1.unpin()
        m2.unpin()
        pKey.unpin()
        error("Failed to update hash")
    }
    val updateRes2 = crypto_generichash_update(state, m2.addressOf(0), message2.length.toULong())
    m1.unpin()
    m2.unpin()
    pKey.unpin()
    if (updateRes2 != 0) {
        error("Failed to update hash")
    }

    val h = hash.pin()
    val finalRes = crypto_generichash_final(state, h.addressOf(0), hash.size.toULong())
    h.unpin()
    if (finalRes != 0) {
        error("Failed to finish hash")
    }
    sodium_free(state)

    println(hash.asString())
     */

    /* Sealed Boxes
    val message = "Message"
    // 1. Create recipient Keypair
    val (pk, sk) = Sodium.cryptoBoxKeypair()
    // 2. Seal a message with the public key
    val ciphertext = Sodium.cryptoBoxSeal(message.asUByteArray(), pk)
    // 3. Open the ciphertext with the public key and private key
    val decrypted = Sodium.cryptoBoxOpen(ciphertext, pk, sk)
    // Prints "Message"
    println(decrypted.asString())
    */

    /*Password hashing: Key derivation
    https://download.libsodium.org/doc/password_hashing/the_argon2i_function
    val password = "test1234"

    val salt = Sodium.randomSalt(crypto_pwhash_SALTBYTES.toInt())
    println("Salt: ${salt.toHexString()}")

    val keylen = crypto_box_SEEDBYTES.toInt()
    val key = Sodium.cryptoPwhash(password, salt.toByteArray(), keylen)
    println("Key: ${key.toHexString()}")
    */

    /*Password hashing: Storage
    val password = "test1234"
    val hashedPassword = Sodium.cryptoPwhashStr(password)
    println("Password: $password")
    println("Hashed Password: ${hashedPassword.stringFromUtf8()}")
    println("Verify: ${Sodium.cryptoPwhashStrVerify(hashedPassword, password)}")
    */
}

fun String.asUByteArray(): UByteArray {
    return UByteArray(length) { this[it].toByte().toUByte() }
}

fun ByteArray.toHexString(): String {
    return Sodium.bin2hex(this.toUByteArray()).stringFromUtf8()
}

fun UByteArray.toHexString(): String {
    return Sodium.bin2hex(this).stringFromUtf8()
}
