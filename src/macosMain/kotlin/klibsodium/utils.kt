package klibsodium

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.pin
import kotlinx.cinterop.usePinned

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
