namespace EncryptorService.Services
{
    public interface IEncryptionService
    {
        public string EncryptString(string plainText, string key);

        public string DecryptString(string encryptedText, string key);

        public string encriptarSHA256(string texto);
    }
}
