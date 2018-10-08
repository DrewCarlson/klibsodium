package demo

import klibsodium.Sodium


fun main(args: Array<String>) {
    if (!Sodium.init()) {
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
    println(decrypted.asByteArray().asString())
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
    println("Hashed Password: ${hashedPassword.contentToString()}")
    println("Verify: ${Sodium.cryptoPwhashStrVerify(hashedPassword, password)}")
    */
}

fun String.asUByteArray(): UByteArray {
    return UByteArray(length) { this[it].toByte().toUByte() }
}

fun ByteArray.toHexString(): String {
    return Sodium.bin2hex(this.toUByteArray()).contentToString()
}

fun ByteArray.asString(): String {
    return map { it.toChar() }.joinToString("")
}

fun UByteArray.toHexString(): String {
    return Sodium.bin2hex(this).contentToString()
}
