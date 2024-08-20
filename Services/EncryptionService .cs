using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptorService.Services
{
    public class EncryptionService : IEncryptionService
    {
        private const int KeySize = 32; // 256 bits para AES

      
        public string EncryptString(string plainText, string key)
        {
            // Convierte la clave a 32 bytes usando SHA-256
            byte[] keyBytes = ConvertKeyToBytes(key);

            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.GenerateIV(); // Genera un vector de inicialización (IV)
                byte[] encrypted = EncryptStringToBytes_Aes(plainText, aes.Key, aes.IV);

                // Combina el IV y los datos encriptados en una sola cadena para simplicidad
                return Convert.ToBase64String(aes.IV) + "." + Convert.ToBase64String(encrypted);
            }
        }

        public string DecryptString(string encryptedText, string key)
        {
            // Convierte la clave a 32 bytes usando SHA-256
            byte[] keyBytes = ConvertKeyToBytes(key);

            // Divide el texto encriptado en partes IV y cipherText
            string[] parts = encryptedText.Split('.');
            if (parts.Length != 2)
            {
                throw new ArgumentException("Cadena encriptada no tiene el formato correcto.");
            }

            byte[] iv = Convert.FromBase64String(parts[0]);
            byte[] cipherText = Convert.FromBase64String(parts[1]);

            return DecryptStringFromBytes_Aes(cipherText, keyBytes, iv);
        }

        private static byte[] ConvertKeyToBytes(string key)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }

        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        return msEncrypt.ToArray();
                    }
                }
            }
        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        public string encriptarSHA256(string texto)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // Computar el hash
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(texto));

                // Convertir el array de bytes a string
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }

                return builder.ToString();
            }
        }
    }
}
