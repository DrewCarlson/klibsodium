package klibsodium

@ExperimentalUnsignedTypes
typealias BoxKeyPair = Pair<UByteArray, UByteArray>

@ExperimentalUnsignedTypes
expect object Sodium {
  val cryptoKdfKeybytes: Int
  val cryptoShorthashBytes: Int
  val cryptoGenerichashBytes: Int
  val cryptoBoxSealbytes: Int
  val cryptoBoxPublickeyBytes: Int
  val cryptoBoxSecretkeyBytes: Int
  val cryptoBoxSeedbytes: Int
  val cryptoPwhashStrbytes: Int
  val cryptoPwhashOpslimitSensitive: Int
  val cryptoPwhashMemlimitSensitive: Int
  val cryptoPwhashOpslimitInteractive: Int
  val cryptoPwhashMemlimitInteractive: Int
  val cryptoPwhashAlgDefault: Int

  fun init(): Boolean

  fun randombytesRandom(): UInt

  fun randombytesUniform(upperBound: UInt): UInt

  fun randombytesBuf(size: ULong): UByteArray

  fun randombytesBufDeterministic(size: ULong, seed: UByteArray): UByteArray

  fun randombytesClose()

  fun bin2hex(bin: UByteArray): ByteArray

  fun cryptoPwhash(password: String, salt: ByteArray, keyLength: Int): UByteArray

  fun cryptoPwhashStr(password: String? = null): ByteArray

  fun cryptoPwhashStrVerify(hashedPassword: ByteArray, password: String? = null): Boolean

  fun cryptoPwhashStrNeedsRehash(
    hashedPassword: ByteArray,
    opslimit: ULong,//TODO: Why doesn't this compile = crypto_pwhash_OPSLIMIT_SENSITIVE.toULong(),
    memlimit: ULong// = crypto_pwhash_MEMLIMIT_SENSITIVE.toULong()
  ): Boolean

  fun cryptoBoxKeypair(
    pkLen: Int = 32,// = crypto_box_PUBLICKEYBYTES.toInt(),
    skLen: Int = 32// = crypto_box_SECRETKEYBYTES.toInt()
  ): BoxKeyPair

  fun cryptoBoxSeal(message: UByteArray, pk: UByteArray): UByteArray

  fun cryptoBoxOpen(ciphertext: UByteArray, pk: UByteArray, sk: UByteArray): UByteArray

  fun cryptoGenerichash(message: UByteArray, key: UByteArray? = null): UByteArray

  fun cryptoKdfKeygen(): UByteArray

  fun cryptoKdfDeriveFromKey(subKeylen: Int, subkeyId: Int, context: ByteArray, masterkey: UByteArray): UByteArray

  fun cryptoShorthashKeygen(): UByteArray

  fun cryptoShorthash(key: UByteArray, shortData: UByteArray): UByteArray
}
