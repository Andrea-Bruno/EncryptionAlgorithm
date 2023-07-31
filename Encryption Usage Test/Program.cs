using EncryptionAlgorithm;
namespace Encryption_Usage_Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var password = "12345678";

            // Example of encryption and decryption of a text

            var text = "Hello, World!";
            Console.WriteLine("Encryption of sentence [" + text + "] using password [" + password + "]");
            var encryptedText = Perform.EncryptText(text, password);
            Console.WriteLine("Encrypted text = " + encryptedText);
            var clearText = Perform.DecryptText(encryptedText, password);
            Console.WriteLine("Clear text = " + clearText);

            // Example of encryption and decryption of binary data

            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            Console.WriteLine("Encryption of data [" + data.Txt() + "] using password [" + password + "]");
            var encryptedData = Perform.EncryptData(data, password);
            Console.WriteLine("Encrypted data = " + encryptedData.Txt());
            var clearData = Perform.DecryptData(encryptedData, password);
            Console.WriteLine("Clear data = " + clearData.Txt());

            Console.ReadKey(); // press any key
        }
    }
    static class Extension
    {
        public static string Txt(this byte[] bytes) => BitConverter.ToString(bytes);
    }

}