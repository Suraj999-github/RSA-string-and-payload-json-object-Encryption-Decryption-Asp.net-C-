using System.Security.Cryptography;

namespace RSA_encryption_decryption.Extensions
{
    public class RsaPayload
    {
         /// <summary>
        /// Creates an instance of RSA provider using the provided private key.
        /// </summary>
        /// <param name="privateKey">The private key in PEM format.</param>
        /// <returns>An instance of RSA provider.</returns>
        public static RSA GetRSAProviderFromPrivateKey(string privateKey)
        {
            RSAParameters rsaParams = ParseRSAPrivateKey(privateKey);
            RSA rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);
            return rsa;
        }

        /// <summary>
        /// Parses the provided private key string into RSAParameters.
        /// </summary>
        /// <param name="privateKey">The private key in PEM format.</param>
        /// <returns>RSAParameters representing the private key.</returns>
        public static RSAParameters ParseRSAPrivateKey(string privateKey)
        {
            // Remove header and footer
            privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "")
                                           .Replace("-----END PRIVATE KEY-----", "")
                                           .Replace("\n", "");
        
            // Decode Base64
            byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
        
            // Parse ASN.1 DER encoded RSA private key
            RSAParameters rsaParams;
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                rsaParams = rsa.ExportParameters(true);
            }
            return rsaParams;
        }
           /// <summary>
           /// Creates an instance of RSA provider using the provided public key.
           /// </summary>
           /// <param name="publicKey">The public key in PEM format.</param>
           /// <returns>An instance of RSA provider.</returns>
           public static RSA GetRSAProviderFromPublicKey(string publicKey)
           {
               RSAParameters rsaParams = ParseRSAPublicKey(publicKey);
               RSA rsa = RSA.Create();
               rsa.ImportParameters(rsaParams);
               return rsa;
           }
           
           /// <summary>
           /// Parses the provided public key string into RSAParameters.
           /// </summary>
           /// <param name="publicKey">The public key in PEM format.</param>
           /// <returns>RSAParameters representing the public key.</returns>
           public static RSAParameters ParseRSAPublicKey(string publicKey)
           {
               // Remove header and footer
               publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "")
                                           .Replace("-----END PUBLIC KEY-----", "")
                                           .Replace("\n", "");
           
               // Decode Base64
               byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
           
               // Parse ASN.1 DER encoded RSA public key
               RSAParameters rsaParams;
               using (var rsa = RSA.Create())
               {
                   rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                   rsaParams = rsa.ExportParameters(false);
               }
               return rsaParams;
           }
    }
}
