using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
        public static string DecryptText(string encryptedText, string password, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled, Action<float> refreshProgressBar = null)
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
        public static string EncryptText(string text, string password, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled, Action<float> refreshProgressBar = null)
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
        public static byte[] DecryptData(byte[] data, string password, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled) => EncryptData(data, password, antiBruteForce);

        /// <summary>
        /// Securely encrypts binary data, using a password as the encryption seed
        /// </summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="password">Encryption password</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        /// <returns>Encrypted data</returns>
        public static byte[] EncryptData(byte[] data, string password, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled, Action<float> refreshProgressBar = null) => Xor(data, GetRandomByteArray(data.Length, password, antiBruteForce, refreshProgressBar));

        /// <summary>
        /// Decrypt a previously encrypted file
        /// </summary>
        /// <param name="file">Full path and file name</param>
        /// <param name="password">The password used for encryption</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        public static void DecryptFile(string file, string password, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled, Action<float> refreshProgressBar = null) => EncryptFile(file, password, antiBruteForce);

        /// <summary>
        /// Securely encrypt a file on disk using a password
        /// </summary>
        /// <param name="file">Full path and file name</param>
        /// <param name="password">Encryption password</param>
        /// <param name="antiBruteForce">If enabled, a large amount of computational power will be used to create the encryption seed (hash), this process takes seconds (depending on the processor power), and makes a trial-based brute force attack difficult. Note: decrypt with the same parameter used for encryption</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        public static void EncryptFile(string file, string password, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled, Action<float> refreshProgressBar = null)
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
        private static byte[] GetRandomByteArray(int size, string seed, AntiBruteForce antiBruteForce = AntiBruteForce.Disabled, Action<float> refreshProgressBar = null)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
            {
                var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(seed).Concat(BitConverter.GetBytes(size)).ToArray()); // Generate a 32 bit seed
                if (antiBruteForce != AntiBruteForce.Disabled)
                    hash = ParallelHash(hash, (int)AntiBruteForce.Disabled, refreshProgressBar: refreshProgressBar);
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

        /// <summary>
        /// Settings for protection against brute force attacks
        /// </summary>
        public enum AntiBruteForce
        {
            /// <summary>
            /// Brute force attack protection is not enabled
            /// </summary>
            Disabled = 0,
            /// <summary>
            /// Provides protection from standard brute force attacks
            /// </summary>
            Standard = 2000000,
            /// <summary>
            /// Strong protection against brute force attacks, an attack attempt would require a computational cloud
            /// </summary>
            Strong = 100000000,
            /// <summary>
            /// Useful for all scenarios in which the security level must be military (the computational force is very high and encryption/decryption will take a long time
            /// </summary>
            Military = 200000000
        }

        private const int DefaultThreads = 8;

        /// <summary>
        /// Support for anti brute force attack!
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="interactions">Number of iterations</param>
        /// <param name="threads">Number of threads to use</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        /// <param name="refreshMs">How often to call the refresh ProgressBar function to update the progress bar (milliseconds)</param>
        /// <param name="entropy">If set, it adds an entropy to the data for which you want to compute the recursive hash: This will obviously change the result.</param>
        /// <returns>hash obtained following the iterations</returns>
        public static byte[] ParallelHash(byte[] data, int interactions = (int)AntiBruteForce.Standard, int threads = DefaultThreads, Action<float> refreshProgressBar = null, int refreshMs = 5000, byte[] entropy = null)
        {
            if (threads == default)
                threads = DefaultThreads;
            if (entropy != null)
                data = data.Concat(entropy);
            var seeds = new byte[threads][];
            var sha256 = SHA256.Create();
            for (byte i = 0; i < threads; i++)
            {
                seeds[i] = sha256.ComputeHash(new byte[i].Concat(data));
            }
            var hashes = new byte[threads][];
#if DEBUG
            var x = new Stopwatch();
            x.Start();
#endif
            var functions = new List<Func<float>>();
            Timer RefreshProgressTimer = null;
            if (refreshProgressBar != null)
            {
                float getInteractionProgress()
                {
                    float total = 0;
                    float n = 0;
                    foreach (var func in functions.ToArray())
                    {
                        total += func();
                        n++;
                    }
                    return n == 0 ? 0 : total / n;
                };
                RefreshProgressTimer = new Timer((obj) => refreshProgressBar(getInteractionProgress()), null, refreshMs, refreshMs);
            }

            Parallel.For(0, threads, thread =>
            {
                hashes[thread] = RecursiveHash(seeds[thread], interactions, functions);
            });
            var result = new byte[hashes[0].Length];
            int progress = 0;
            for (progress = 0; progress < threads; progress++)
            {
                result = Xor(result, hashes[progress]);
            }
            RefreshProgressTimer?.Change(Timeout.Infinite, Timeout.Infinite);
#if DEBUG
            x.Stop();
            Debug.WriteLine(x.Elapsed);
#endif
            return result;
        }

        private static byte[] Concat(this byte[] thisArray, byte[] array)
        {
            var result = new byte[thisArray.Length + array.Length];
            Buffer.BlockCopy(thisArray, 0, result, 0, thisArray.Length);
            Buffer.BlockCopy(array, 0, result, thisArray.Length, array.Length);
            return result;
        }

        private static byte[] RecursiveHash(byte[] data, int interactions, List<Func<float>> progressList = null)
        {
            var sha256 = SHA256.Create();
            byte[] hash = data;
            int progress = 0;
            if (progressList != null)
            {
                lock (progressList)
                {
                    Func<float> getInteractionProgress = () => progress / (float)interactions;
                    progressList.Add(getInteractionProgress);
                }
            }
            for (progress = 0; progress < interactions; progress++)
            {
                hash = sha256.ComputeHash(hash);
            }
            return hash;
        }
    }
}
