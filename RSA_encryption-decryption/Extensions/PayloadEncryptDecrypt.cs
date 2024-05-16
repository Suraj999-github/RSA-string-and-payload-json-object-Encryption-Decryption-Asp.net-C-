using System.Security.Cryptography;
using System.Text;

namespace RSA_encryption_decryption.Extensions
{
    public class PayloadEncryptDecrypt
    {
       // https://asecuritysite.com/ecc/keys rsa 1024
        public static string SIGNING_PRIVATE_KEY()
        {
             return @"
                    MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJUromb8C/bbVwfx
                    XgvXr+dHINTTqQTYEUxpwiLkF5Qj+BukILDVIbitaVp9wa4z+ttviKmw4Zw+tG/t
                    cqu2YVlJjDb8cDUDLcgTf0RwUYJY8PSvRHsyWmMmgzcGtkg2K9jmyDc3b5MQlqZn
                    kZKvRe9GRpF1cD/iNOw9I0R0PiVVAgMBAAECgYAHJQ7jReFA0qKpg7sQcCVBu5tr
                    9jNbQwoZEdu1lh03AD4K/OJ/9cVmtg+cwPc848p5Ji9yiUFVHX/A+KuMY/DnpgRb
                    VETP90/ATF5LAbj4a8i0wC7gPSF3NlUelbJCP0oL4IZJJ/IqW4gYjsUVP7cYttNx
                    IP2Lslyvjh3gy3NzpQJBAN/vH7TlSNzUYsZxsA7rtHpgixZe0icIzdIhOAdmcBpi
                    OIEfnTSgG8+9Kto7Y8N3aWFaTPhoBv73yAGzINol9YMCQQCqh9vGbh1RMD4QPyJd
                    peT4KXJqCJzkXBNt9sIsLgDsN6FURjDzIC4fnqyor89v5aZHGhrcO6CNFgCHAPzB
                    TVpHAkBREBL+PPH/XrLS+1ysSg7vLfurgW+5yaoYIwZRR3fVVTD3LSaPYlYvAV99
                    2HnozFVNdI7gbWf67F9unhWKYqtZAkEAnKK/vysDqMBcMYYcJdKsVzmSy0xv992P
                    RzEht3zmAhMzD3qNmbQUSZzw0Nzz978EFUkoJORsG0t7XoYMo+1OHwJAD/U4pGHR
                    5HLa+euDPFJNJwHiQMBSdjEIZDqmTglzLm6FtPKB6pfijFbT9kVULGsDgxNGZjsG
                    mtYx3wcOWEkeZA==";

        }
        public static string DECRYPTING_PRIVATE_KEY()
        {
             return @"
                    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVK6Jm/Av221cH8V4L16/nRyDU
                    06kE2BFMacIi5BeUI/gbpCCw1SG4rWlafcGuM/rbb4ipsOGcPrRv7XKrtmFZSYw2
                    /HA1Ay3IE39EcFGCWPD0r0R7MlpjJoM3BrZINivY5sg3N2+TEJamZ5GSr0XvRkaR
                    dXA/4jTsPSNEdD4lVQIDAQAB
                    ";
        }
        // Method to encrypt string using RSA encryption
/// <summary>
/// Method to encrypt a string using RSA encryption.
/// </summary>
/// <param name="plainText">The string to be encrypted.</param>
/// <returns>The encrypted string in Base64 format.</returns>
public static string ENCRYPT_STRING(string plainText)
{
    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
    {
        rsa.ImportParameters(RsaPayload.ParseRSAPublicKey(DECRYPTING_PRIVATE_KEY()));
        byte[] encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), true);
        return Convert.ToBase64String(encryptedBytes);
    }
}

        // Method to decrypt string using RSA decryption
        /// <summary>
/// Method to decrypt string using RSA decryption.
/// </summary>
/// <param name="encryptedText">The encrypted text to be decrypted.</param>
/// <returns>The decrypted string.</returns>
public static string DECRYPT_STRING(string encryptedText)
{
    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
    {
        rsa.ImportParameters(RsaPayload.ParseRSAPrivateKey(SIGNING_PRIVATE_KEY()));
        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
        byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, true);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}
    }
}
