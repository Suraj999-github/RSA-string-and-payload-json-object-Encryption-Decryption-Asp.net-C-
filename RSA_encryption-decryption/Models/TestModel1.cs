namespace RSA_encryption_decryption.Models
{
    public class TestModel1
    {
        public int Id { get; set; }
        public string Name { get; set; }            
        public string Password { get; set; }
        public string Secret { get; set; }
        public string Type { get; set; }
    }
    public class TestModel2
    {
        public string Type { get; set; }
        public int Id { get; set; }
        public string Secret { get; set; }
        public string Name { get; set; }       
        public string Password { get; set; }

    }
}
