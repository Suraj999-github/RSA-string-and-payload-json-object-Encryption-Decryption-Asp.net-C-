using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RSA_encryption_decryption.Extensions;
using RSA_encryption_decryption.Models;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;

namespace RSA_encryption_decryption.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            var plainTextData = "test simple";
            Console.WriteLine("plainTextData : " + plainTextData);
            var s1 = RsaServiceProvider.RSA_ENCRYPTION(plainTextData);
            var s3 = RsaServiceProvider.RSA_ENCRYPTION(plainTextData);
            var s2 = RsaServiceProvider.RSA_DECRYPT(s1);
            var s4 = RsaServiceProvider.RSA_SHARED_KEY_COMPARE(s1,s3);
            ViewBag.S1 = s1;
            ViewBag.S = plainTextData;
            ViewBag.S3 = s3;
            ViewBag.S2 = s2;
            ViewBag.S4 = s4;
            return View();
        }

        public IActionResult Privacy()
        {
            TestModel1 m1= new TestModel1();
            m1.Id = 1;
            m1.Name = "suraj";
            m1.Password = "abc@12345";
            m1.Secret = "sfsdf";
            m1.Type = "secure";
           
            var p1 = JsonConvert.SerializeObject(m1);
            var jobj1 = JObject.Parse(p1);

            TestModel2 m2 = new TestModel2();
            m2.Id = 1;
            m2.Name = "suraj";
            m2.Password = "abc@12345";
            m2.Secret = "sfsdf";
            m2.Type = "secure";
            var p2 = JsonConvert.SerializeObject(m2);
            var jobj2 = JObject.Parse(p2);          
           
            // Convert object to JSON string
            string jsonString = JsonConvert.SerializeObject(jobj1);

           // Encrypt and Decrypt the JSON string
           string encryptedJson = PayloadEncryptDecrypt.ENCRYPT_STRING(jsonString);
           string decryptedJson = PayloadEncryptDecrypt.DECRYPT_STRING(encryptedJson);

            // Deserialize JSON string back to object
            var jobj3 = JObject.Parse(decryptedJson);
        
            // Compare the original and decrypted objects
            var areEqual = JToken.DeepEquals(jobj2, jobj3);
               // bool areEqual = jobj2.Equals(jobj3);
                Console.WriteLine($"Are the objects equal? {areEqual}");
                   ViewBag.S1 = jobj1;
                   ViewBag.S5 = jobj3;
                   ViewBag.S6 = areEqual;
                   ViewBag.S3 = encryptedJson;
                   ViewBag.S2 = jobj2;
                   ViewBag.S4 = decryptedJson;


            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
