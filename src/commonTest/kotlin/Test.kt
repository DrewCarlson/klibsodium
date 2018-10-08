import klibsodium.Sodium
import kotlin.test.BeforeTest
import kotlin.test.Test

class Test {

  @BeforeTest
  fun setUp() {
    Sodium.init()
  }

  @Test
  fun test() {
    val password = "test1234"
    val hashedPassword = Sodium.cryptoPwhashStr(password)
    println("Password: $password")
    println("Hashed Password: ${hashedPassword.contentToString()}")
    println("Verify: ${Sodium.cryptoPwhashStrVerify(hashedPassword, password)}")
  }
}
