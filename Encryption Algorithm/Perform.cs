using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionAlgorithm
{
    public static class Perform
    {
        /// <summary>
        /// Decrypt encrypted text
        /// </summary>
        /// <param name="encryptedText">Encrypted text</param>
        /// <param name="password">The password used for encryption</param>
        /// <returns>Clear text</returns>
        public static string DecryptText(string encryptedText, string password)
        {
            var encrypted = Convert.FromBase64String(encryptedText);
            var decrypted = EncryptData(encrypted, password);
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Securely encrypts text, using a password as the encryption seed
        /// </summary>
        /// <param name="text">Text to be decryptad</param>
        /// <param name="password">The password used for encryption</param>
        /// <returns>Encrypted text</returns>
        public static string EncryptText(string text, string password)
        {
            var encrypted = EncryptData(Encoding.UTF8.GetBytes(text), password);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypt a binary data
        /// </summary>
        /// <param name="data">Data to be decryptad</param>
        /// <param name="password">The password used for encryption</param>
        /// <returns>Clear data</returns>
        public static byte[] DecryptData(byte[] data, string password) => EncryptData(data, password);

        /// <summary>
        /// Securely encrypts binary data, using a password as the encryption seed
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="password">Encryption password</param>
        /// <returns>Encrypted data</returns>
        public static byte[] EncryptData(byte[] data, string password) => Xor(data, GetRandomByteArray(data.Length, password));

        /// <summary>
        /// Decrypt a previously encrypted file
        /// </summary>
        /// <param name="file">Full path and file name</param>
        /// <param name="password">The password used for encryption</param>
        public static void DecryptFile(string file, string password) => EncryptFile(file, password);

        /// <summary>
        /// Securely encrypt a file on disk using a password
        /// </summary>
        /// <param name="file">Full path and file name</param>
        /// <param name="password">Encryption password</param>
        public static void EncryptFile(string file, string password)
        {
            using (var fs = new FileStream(file, FileMode.Open))
            {
                int len = (int)fs.Length;
                var data = new byte[len];
                fs.Read(data, 0, len);
                data = Xor(data, GetRandomByteArray(data.Length, password));
                fs.Write(data, 0, data.Length);
                fs.Close();
            }
        }
        private static byte[] GetRandomByteArray(int size, string seed)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
            {
                var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(seed));
                var hl = hash.Length;
                var parts = (int)Math.Ceiling((double)size / hl);
                byte[] b = new byte[parts * hl];
                var p = 0;
                for (int i = 0; i < parts; i++)
                {
                    p = i * 32;
                    hash = algorithm.ComputeHash(hash);
                    Array.Copy(hash, 0, b, p, hl);
                }
                Array.Resize(ref b, size);
                return b;
            }
        }
        private static byte[] Xor(byte[] key, byte[] PAN)
        {
            byte[] result = new byte[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                result[i] = (byte)(key[i] ^ PAN[i]);
            }
            return result;
        }
    }
}
