using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;

namespace RSA_encryption_decryption.Extensions
{
    public class RsaServiceProvider
    {
         /// <summary>
        /// Imports a private RSA key from a PEM-encoded string and returns an instance of <see cref="RSACryptoServiceProvider"/>.
        /// </summary>
        /// <returns>An instance of <see cref="RSACryptoServiceProvider"/> containing the imported private RSA key.</returns>
        public static RSACryptoServiceProvider IMPORT_PRIVATE_KEY()
        {
            PemReader pr = new PemReader(new StringReader(RsaKeys.RSA_PRIVATE_KEY()));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
        
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
        
        /// <summary>
        /// Imports a public RSA key from a PEM-encoded string and returns an instance of <see cref="RSACryptoServiceProvider"/>.
        /// </summary>
        /// <returns>An instance of <see cref="RSACryptoServiceProvider"/> containing the imported public RSA key.</returns>
        public static RSACryptoServiceProvider IMPORT_PUBLIC_KEY()
        {
            PemReader pr = new PemReader(new StringReader(RsaKeys.RSA_PUBLIC_KEY()));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);
        
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
              
        /// <summary>
        /// Encrypts the plain text data using RSA encryption.
        /// </summary>
        /// <param name="plainTextData">The plain text data to be encrypted.</param>
        /// <returns>A Base64-encoded string representation of the encrypted data.</returns>
        public static string RSA_ENCRYPTION(string plainTextData)
        {
            //for encryption, always handle bytes...
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);
        
            //apply pkcs#1.5 padding and encrypt our data
            RSACryptoServiceProvider RSApublicKey = IMPORT_PUBLIC_KEY();
            var bytesCypherText = RSApublicKey.Encrypt(bytesPlainTextData, false);
        
            //we might want a string representation of our cypher text... base64 will do
            var cypherText = Convert.ToBase64String(bytesCypherText);
            return cypherText;
        }

        /// <summary>
        /// Decrypts the cipher text and returns the original plain text data.
        /// </summary>
        /// <param name="cypherText">The Base64-encoded string representation of the cipher text to be decrypted.</param>
        /// <returns>The original plain text data.</returns>
        public static string RSA_DECRYPT(string cypherText)
        {
            //first, get our bytes back from the base64 string ...
            var bytesCypherText = Convert.FromBase64String(cypherText);
            //we want to decrypt, therefore we need a csp and load our private key
        
            //decrypt and strip pkcs#1.5 padding
            RSACryptoServiceProvider RSAprivateKey = IMPORT_PRIVATE_KEY();
            var  bytesPlainTextData = RSAprivateKey.Decrypt(bytesCypherText, false);
        
            //get our original plainText back...
            var plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);
            System.Diagnostics.Debug.WriteLine("DecryptData : " + plainTextData);
            return plainTextData;
        }

        /// <summary>
        /// Compares the decrypted plaintexts from two different cipher texts.
        /// </summary>
        /// <param name="requestedCypherText">The Base64-encoded string representation of the requested cipher text.</param>
        /// <param name="systemGeneratedCypherText">The Base64-encoded string representation of the system-generated cipher text.</param>
        /// <returns>True if the decrypted plaintexts are the same, otherwise false.</returns>
        public static bool RSA_SHARED_KEY_COMPARE(string requestedCypherText, string systemGeneratedCypherText)
        {
            // Convert the Base64-encoded strings to bytes
            var c1 = Convert.FromBase64String(requestedCypherText);
            var c2 = Convert.FromBase64String(systemGeneratedCypherText);

            // Load the private key
            RSACryptoServiceProvider RSAprivateKey = IMPORT_PRIVATE_KEY();

            // Decrypt the cipher texts and compare the decrypted plaintexts
            var b1 = RSAprivateKey.Decrypt(c1, false);
            var b2 = RSAprivateKey.Decrypt(c2, false);

            // Compare the decrypted plaintexts
            return System.Text.Encoding.Unicode.GetString(b1) == System.Text.Encoding.Unicode.GetString(b2);
        }
    }
}
