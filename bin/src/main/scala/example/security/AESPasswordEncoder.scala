package example.security

import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.BadPaddingException
import javax.crypto.spec.IvParameterSpec
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import java.util.Base64

import org.springframework.security.crypto.password.PasswordEncoder

class AESPasswordEncoder
extends org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()
with PasswordEncoder {

    val password = "@amG89>"
    val salt = "blacknoir"

    val ivParameterSpec :IvParameterSpec =  generateIv()

    val key :SecretKey = getKeyFromPassword(password,salt)

    override def encode(rawPassword :CharSequence) :String =
    {
      try {
        val res = encryptPasswordBased(rawPassword.toString(), key, ivParameterSpec)
        return super.encode(res)
      } catch {
        case e: Exception => {}
      }
      return super.encode(rawPassword)
    }

    override def matches(rawPassword :CharSequence, encodedPassword :String) :Boolean =
    {
     try {
       val res = encryptPasswordBased(rawPassword.toString(), key, ivParameterSpec)
       return super.matches(res, encodedPassword)
     }catch{
      case e :Exception => return false
      }
    }

    @throws ( classOf[Exception]  )
    def encrypt(algorithm :String, input :String, key :SecretKey, iv :IvParameterSpec) : String =
    {
        val cipher :Cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        val cipherText :Array[Byte] = cipher.doFinal(input.getBytes())
        return Base64.getEncoder().encodeToString(cipherText)
    }

    @throws (classOf[Exception])
    def generateKey(n :Int) :SecretKey = {
        val keyGenerator :KeyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(n)
        return keyGenerator.generateKey()
    }

    @throws (classOf[Exception] )
    def getKeyFromPassword(password :String, salt :String) : SecretKey =
    {
        val factory :SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec :KeySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256)
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES")
    }

    def generateIv() :IvParameterSpec = {
        val iv = new Array[Byte](16)
        new SecureRandom().nextBytes(iv)
        return new IvParameterSpec(iv)
    }

    @throws ( classOf[Exception] )
    def encryptPasswordBased(plainText :String, key :SecretKey, iv :IvParameterSpec) : String =
    {
        val cipher :Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()))
    }
}
