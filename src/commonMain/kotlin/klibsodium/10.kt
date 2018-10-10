package klibsodium


expect fun randombytes(): UByteArray

expect fun randombytes_buf(size: ULong): UByteArray

expect fun randombytes_buf_deterministic(size: ULong, seed: UByteArray): UByteArray

expect fun randombytes_close()

expect fun randombytes_implementation_name(): ByteArray

expect fun randombytes_random(): UInt

expect fun randombytes_seedbytes(): ULong

//TODO: public fun randombytes_set_implementation(impl: kotlinx.cinterop.CValuesRef<libsodium.randombytes_implementation>?): kotlin.Int { /* compiled code */ }

expect fun randombytes_stir()

expect fun randombytes_uniform(upperBound: UInt): UInt

expect fun sodium_add(a: ULong, b: ULong): ULong

expect fun sodium_add(a: UInt, b: UInt): UInt

expect fun sodium_allocarray(count: ULong, size: ULong): UByteArray

expect fun sodium_base642bin(binLenMax: ULong, b64: String? = null, ignore: kotlin.String? = null, bin_len: ULong, b64_end: ByteArray?, variant: Int): Int { /* compiled code */ }

public fun sodium_base64_encoded_len(bin_len: platform.posix.size_t /* = kotlin.ULong */, variant: kotlin.Int): platform.posix.size_t /* = kotlin.ULong */ { /* compiled code */ }

public fun sodium_bin2base64(b64: kotlinx.cinterop.CValuesRef<kotlinx.cinterop.ByteVar /* = kotlinx.cinterop.ByteVarOf<kotlin.Byte> */>?, b64_maxlen: platform.posix.size_t /* = kotlin.ULong */, bin: kotlinx.cinterop.CValuesRef<kotlinx.cinterop.UByteVar /* = kotlinx.cinterop.UByteVarOf<kotlin.UByte> */>?, bin_len: platform.posix.size_t /* = kotlin.ULong */, variant: kotlin.Int): kotlinx.cinterop.CPointer<kotlinx.cinterop.ByteVar /* = kotlinx.cinterop.ByteVarOf<kotlin.Byte> */>? { /* compiled code */ }

expect fun sodium_bin2hex(bin: UByteArray): ByteArray
