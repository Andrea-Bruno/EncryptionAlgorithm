using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using static AntiBruteForce.Perform;
namespace EncryptionAlgorithm
{
    /// <summary>
    /// Access to encryption features
    /// </summary>
    public static class Perform
    {
        /// <summary>
        /// Decrypt encrypted text
        /// </summary>
        /// <param name="encryptedText">Encrypted text</param>
        /// <param name="password">The password used for encryption</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        /// <returns>Clear text</returns>
        public static string DecryptText(string encryptedText, string password, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled, Action<float> refreshProgressBar = null)
        {
            var encrypted = Convert.FromBase64String(encryptedText);
            var decrypted = EncryptData(encrypted, password, antiBruteForce, refreshProgressBar);
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Securely encrypts text, using a password as the encryption seed
        /// </summary>
        /// <param name="text">Text to be decrypted</param>
        /// <param name="password">The password used for encryption</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        /// <returns>Encrypted text</returns>
        public static string EncryptText(string text, string password, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled, Action<float> refreshProgressBar = null)
        {
            var encrypted = EncryptData(Encoding.UTF8.GetBytes(text), password, antiBruteForce, refreshProgressBar);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypt a binary data
        /// </summary>
        /// <param name="data">Data to be decrypted</param>
        /// <param name="password">The password used for encryption</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <returns>Clear data</returns>
        public static byte[] DecryptData(byte[] data, string password, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled) => EncryptData(data, password, antiBruteForce);

        /// <summary>
        /// Securely encrypts binary data, using a password as the encryption seed
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="password">Encryption password</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        /// <returns>Encrypted data</returns>
        public static byte[] EncryptData(byte[] data, string password, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled, Action<float> refreshProgressBar = null) => Xor(data, GetRandomByteArray(data.Length, password, antiBruteForce, refreshProgressBar));

        /// <summary>
        /// Decrypt a previously encrypted file
        /// </summary>
        /// <param name="file">Full path and file name</param>
        /// <param name="password">The password used for encryption</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        public static void DecryptFile(string file, string password, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled, Action<float> refreshProgressBar = null) => EncryptFile(file, password, antiBruteForce);

        /// <summary>
        /// Securely encrypt a file on disk using a password
        /// </summary>
        /// <param name="file">Full path and file name</param>
        /// <param name="password">Encryption password</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        public static void EncryptFile(string file, string password, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled, Action<float> refreshProgressBar = null)
        {
            using (var fs = new FileStream(file, FileMode.Open))
            {
                int len = (int)fs.Length;
                var data = new byte[len];
                fs.Read(data, 0, len);
                data = Xor(data, GetRandomByteArray(data.Length, password, antiBruteForce, refreshProgressBar));
                fs.Write(data, 0, data.Length);
                fs.Close();
            }
        }
        private static byte[] GetRandomByteArray(int size, string seed, AntiBruteForceInteractions antiBruteForce = AntiBruteForceInteractions.Disabled, Action<float> refreshProgressBar = null)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
            {
                var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(seed).Concat(BitConverter.GetBytes(size)).ToArray()); // Generate a 32 bit seed
                if (antiBruteForce != AntiBruteForceInteractions.Disabled)
                    hash = ParallelHash(hash, (int)AntiBruteForceInteractions.Disabled, refreshProgressBar: refreshProgressBar);
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
    }
}
