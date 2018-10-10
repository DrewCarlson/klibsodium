package klibsodium

@ExperimentalUnsignedTypes
typealias BoxKeyPair = Pair<UByteArray, UByteArray>
@ExperimentalUnsignedTypes
typealias SignKeyPair = Pair<UByteArray, UByteArray>

expect val SODIUM_LIBRARY_MINIMAL: kotlin.Int 
expect val SODIUM_LIBRARY_VERSION_MAJOR: kotlin.Int 
expect val SODIUM_LIBRARY_VERSION_MINOR: kotlin.Int 
expect val SODIUM_SIZE_MAX: kotlin.ULong 
expect val SODIUM_VERSION_STRING: kotlin.String 
expect val crypto_aead_aes256gcm_ABYTES: kotlin.UInt 
expect val crypto_aead_aes256gcm_KEYBYTES: kotlin.UInt 
expect val crypto_aead_aes256gcm_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_aead_aes256gcm_NPUBBYTES: kotlin.UInt 
expect val crypto_aead_aes256gcm_NSECBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_ABYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_IETF_ABYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_IETF_KEYBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_aead_chacha20poly1305_IETF_NPUBBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_IETF_NSECBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_KEYBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_aead_chacha20poly1305_NPUBBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_NSECBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_ietf_ABYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_ietf_KEYBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_aead_chacha20poly1305_ietf_NPUBBYTES: kotlin.UInt 
expect val crypto_aead_chacha20poly1305_ietf_NSECBYTES: kotlin.UInt 
expect val crypto_aead_xchacha20poly1305_IETF_ABYTES: kotlin.UInt 
expect val crypto_aead_xchacha20poly1305_IETF_KEYBYTES: kotlin.UInt 
expect val crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX: kotlin.ULong
expect val crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: kotlin.UInt
expect val crypto_aead_xchacha20poly1305_IETF_NSECBYTES: kotlin.UInt
expect val crypto_aead_xchacha20poly1305_ietf_ABYTES: kotlin.UInt 
expect val crypto_aead_xchacha20poly1305_ietf_KEYBYTES: kotlin.UInt 
expect val crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: kotlin.UInt 
expect val crypto_aead_xchacha20poly1305_ietf_NSECBYTES: kotlin.UInt 
expect val crypto_auth_BYTES: kotlin.UInt 
expect val crypto_auth_KEYBYTES: kotlin.UInt 
expect val crypto_auth_PRIMITIVE: kotlin.String 
expect val crypto_auth_hmacsha256_BYTES: kotlin.UInt 
expect val crypto_auth_hmacsha256_KEYBYTES: kotlin.UInt 
expect val crypto_auth_hmacsha512256_BYTES: kotlin.UInt 
expect val crypto_auth_hmacsha512256_KEYBYTES: kotlin.UInt 
expect val crypto_auth_hmacsha512_BYTES: kotlin.UInt 
expect val crypto_auth_hmacsha512_KEYBYTES: kotlin.UInt 
expect val crypto_box_BEFORENMBYTES: kotlin.UInt 
expect val crypto_box_BOXZEROBYTES: kotlin.UInt 
expect val crypto_box_MACBYTES: kotlin.UInt 
expect val crypto_box_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_box_NONCEBYTES: kotlin.UInt 
expect val crypto_box_PRIMITIVE: kotlin.String 
expect val crypto_box_PUBLICKEYBYTES: kotlin.UInt 
expect val crypto_box_SEALBYTES: kotlin.UInt 
expect val crypto_box_SECRETKEYBYTES: kotlin.UInt 
expect val crypto_box_SEEDBYTES: kotlin.UInt 
expect val crypto_box_ZEROBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_MACBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX: kotlin.ULong 
expect val crypto_box_curve25519xsalsa20poly1305_NONCEBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_SEEDBYTES: kotlin.UInt 
expect val crypto_box_curve25519xsalsa20poly1305_ZEROBYTES: kotlin.UInt 
expect val crypto_core_hchacha20_CONSTBYTES: kotlin.UInt 
expect val crypto_core_hchacha20_INPUTBYTES: kotlin.UInt 
expect val crypto_core_hchacha20_KEYBYTES: kotlin.UInt 
expect val crypto_core_hchacha20_OUTPUTBYTES: kotlin.UInt 
expect val crypto_core_hsalsa20_CONSTBYTES: kotlin.UInt 
expect val crypto_core_hsalsa20_INPUTBYTES: kotlin.UInt 
expect val crypto_core_hsalsa20_KEYBYTES: kotlin.UInt 
expect val crypto_core_hsalsa20_OUTPUTBYTES: kotlin.UInt 
expect val crypto_core_salsa2012_CONSTBYTES: kotlin.UInt 
expect val crypto_core_salsa2012_INPUTBYTES: kotlin.UInt 
expect val crypto_core_salsa2012_KEYBYTES: kotlin.UInt 
expect val crypto_core_salsa2012_OUTPUTBYTES: kotlin.UInt 
expect val crypto_core_salsa208_CONSTBYTES: kotlin.UInt 
expect val crypto_core_salsa208_INPUTBYTES: kotlin.UInt 
expect val crypto_core_salsa208_KEYBYTES: kotlin.UInt 
expect val crypto_core_salsa208_OUTPUTBYTES: kotlin.UInt 
expect val crypto_core_salsa20_CONSTBYTES: kotlin.UInt 
expect val crypto_core_salsa20_INPUTBYTES: kotlin.UInt 
expect val crypto_core_salsa20_KEYBYTES: kotlin.UInt 
expect val crypto_core_salsa20_OUTPUTBYTES: kotlin.UInt 
expect val crypto_generichash_BYTES: kotlin.UInt 
expect val crypto_generichash_BYTES_MAX: kotlin.UInt 
expect val crypto_generichash_BYTES_MIN: kotlin.UInt 
expect val crypto_generichash_KEYBYTES: kotlin.UInt 
expect val crypto_generichash_KEYBYTES_MAX: kotlin.UInt 
expect val crypto_generichash_KEYBYTES_MIN: kotlin.UInt
expect val crypto_generichash_PRIMITIVE: kotlin.String 
expect val crypto_generichash_blake2b_BYTES: kotlin.UInt 
expect val crypto_generichash_blake2b_BYTES_MAX: kotlin.UInt 
expect val crypto_generichash_blake2b_BYTES_MIN: kotlin.UInt 
expect val crypto_generichash_blake2b_KEYBYTES: kotlin.UInt 
expect val crypto_generichash_blake2b_KEYBYTES_MAX: kotlin.UInt 
expect val crypto_generichash_blake2b_KEYBYTES_MIN: kotlin.UInt 
expect val crypto_generichash_blake2b_PERSONALBYTES: kotlin.UInt 
expect val crypto_generichash_blake2b_SALTBYTES: kotlin.UInt 
expect val crypto_hash_BYTES: kotlin.UInt 
expect val crypto_hash_PRIMITIVE: kotlin.String 
expect val crypto_hash_sha256_BYTES: kotlin.UInt 
expect val crypto_hash_sha512_BYTES: kotlin.UInt 
expect val crypto_kdf_BYTES_MAX: kotlin.Int 
expect val crypto_kdf_BYTES_MIN: kotlin.Int 
expect val crypto_kdf_CONTEXTBYTES: kotlin.Int 
expect val crypto_kdf_KEYBYTES: kotlin.Int 
expect val crypto_kdf_PRIMITIVE: kotlin.String 
expect val crypto_kdf_blake2b_BYTES_MAX: kotlin.Int 
expect val crypto_kdf_blake2b_BYTES_MIN: kotlin.Int 
expect val crypto_kdf_blake2b_CONTEXTBYTES: kotlin.Int 
expect val crypto_kdf_blake2b_KEYBYTES: kotlin.Int 
expect val crypto_kx_PRIMITIVE: kotlin.String 
expect val crypto_kx_PUBLICKEYBYTES: kotlin.Int 
expect val crypto_kx_SECRETKEYBYTES: kotlin.Int 
expect val crypto_kx_SEEDBYTES: kotlin.Int 
expect val crypto_kx_SESSIONKEYBYTES: kotlin.Int 
expect val crypto_onetimeauth_BYTES: kotlin.UInt 
expect val crypto_onetimeauth_KEYBYTES: kotlin.UInt 
expect val crypto_onetimeauth_PRIMITIVE: kotlin.String
expect val crypto_onetimeauth_poly1305_BYTES: kotlin.UInt 
expect val crypto_onetimeauth_poly1305_KEYBYTES: kotlin.UInt 
expect val crypto_pwhash_ALG_ARGON2I13: kotlin.Int 
expect val crypto_pwhash_ALG_ARGON2ID13: kotlin.Int 
expect val crypto_pwhash_ALG_DEFAULT: kotlin.Int 
expect val crypto_pwhash_BYTES_MAX: kotlin.ULong 
expect val crypto_pwhash_BYTES_MIN: kotlin.UInt
expect val crypto_pwhash_OPSLIMIT_INTERACTIVE: kotlin.UInt
expect val crypto_pwhash_MEMLIMIT_INTERACTIVE: kotlin.UInt 

expect fun sodium_init(): Boolean

expect fun crypto_pwhash(password: String, salt: ByteArray, keyLength: Int): UByteArray

expect fun crypto_pwhash_str(password: String? = null): ByteArray

expect fun crypto_pwhash_str_verify(hashedPassword: ByteArray, password: String? = null): Boolean

expect fun crypto_pwhash_str_needs_rehash(
  hashedPassword: ByteArray,
  opslimit: ULong = crypto_pwhash_OPSLIMIT_INTERACTIVE.toULong(),
  memlimit: ULong = crypto_pwhash_MEMLIMIT_INTERACTIVE.toULong()
): Boolean

expect fun crypto_box_keypair(
  pkLen: Int = crypto_box_PUBLICKEYBYTES.toInt(),
  skLen: Int = crypto_box_SECRETKEYBYTES.toInt()
): BoxKeyPair

expect fun crypto_box_seal(message: UByteArray, pk: UByteArray): UByteArray

expect fun crypto_box_open(ciphertext: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray

expect fun crypto_generichash(message: UByteArray, key: UByteArray? = null): UByteArray

expect fun crypto_kdf_keygen(): UByteArray

expect fun crypto_kdf_derive_from_key(subKeylen: Int, subkeyId: Int, context: ByteArray, masterkey: UByteArray): UByteArray

expect fun crypto_shorthash_keygen(): UByteArray

expect fun crypto_shorthash(key: UByteArray, shortData: UByteArray): UByteArray

expect fun crypto_sign_keypair(): SignKeyPair

expect fun crypto_sign(message: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray
