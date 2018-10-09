package demo

import klibsodium.*


fun main(args: Array<String>) {
    if (!sodium_init()) {
        error("sodium_init() failed.")
    }

    /*
    Shorthashing
    https://download.libsodium.org/doc/hashing/short-input_hashing
    val key = Sodium.crypto_shorthash_keygen()
    val hash = Sodium.crypto_shorthash(key, "data".asUByteArray())

    println(hash.asString())
    */

    /* KDF
    https://download.libsodium.org/doc/key_derivation
    val context = "Examples" // Must be 8 characters
    val masterkey = Sodium.crypto_kdf_keygen()
    println("Masterkey: ${masterkey.asString()}")

    val subkey1 = Sodium.crypto_kdf_derive_from_key(32, 1, context.toUtf8(), masterkey)
    val subkey2 = Sodium.crypto_kdf_derive_from_key(32, 2, context.toUtf8(), masterkey)
    val subkey3 = Sodium.crypto_kdf_derive_from_key(64, 3, context.toUtf8(), masterkey)

    println("subkey1: ${subkey1.asString()}")
    println("subkey2: ${subkey2.asString()}")
    println("subkey3: ${subkey3.asString()}")
    */

    /* Generic hash, single-part, no key
    val message = "Message"
    val hash = Sodium.crypto_generichash(message.asUByteArray())
    println(hash.asString())
    */

    /* Generic hash, single-part, with key
    val message = "Message"
    val key = Sodium.randomSalt(crypto_generichash_KEYBYTES.toInt())
    val hash = Sodium.crypto_generichash(message.asUByteArray(), key)
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
    val (pk, sk) = Sodium.crypto_box_keypair()
    // 2. Seal a message with the public key
    val ciphertext = Sodium.crypto_box_seal(message.asUByteArray(), pk)
    // 3. Open the ciphertext with the public key and private key
    val decrypted = Sodium.crypto_box_open(ciphertext, pk, sk)
    // Prints "Message"
    println(decrypted.asByteArray().asString())
     */

    /*Password hashing: Key derivation
    https://download.libsodium.org/doc/password_hashing/the_argon2i_function
    val password = "test1234"

    val salt = Sodium.randomSalt(crypto_pwhash_SALTBYTES.toInt())
    println("Salt: ${salt.toHexString()}")

    val keylen = crypto_box_SEEDBYTES.toInt()
    val key = Sodium.crypto_pwhash(password, salt.toByteArray(), keylen)
    println("Key: ${key.toHexString()}")
    */

    /*Password hashing: Storage
    val password = "test1234"
    val hashedPassword = crypto_pwhash_str(password)
    println("Password: $password")
    println("Hashed Password: ${hashedPassword.asString()}")
    println("Verify: ${crypto_pwhash_str_verify(hashedPassword, password)}")
    */
}

fun String.asUByteArray(): UByteArray {
    return UByteArray(length) { this[it].toByte().toUByte() }
}

fun ByteArray.toHexString(): String {
    return sodium_bin2hex(this.toUByteArray()).contentToString()
}

fun ByteArray.asString(): String {
    return map { it.toChar() }.joinToString("")
}

fun UByteArray.toHexString(): String {
    return sodium_bin2hex(this).contentToString()
}
