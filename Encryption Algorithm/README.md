# Cross-platform dotnet encryption and decryption library

## Simple to use and effective encryption algorithm

## Contents: Encryption and decryption algorithm for text, binary data (byte array), and files.

Very effective and powerful encryption algorithm, easy to use (only one command line), the public repository on github also contains a console project with an example of use.

*Support:*

- File encryption
- Text encryption
- Encryption of binary data
- Protection against brute force attacks

## Example of use
```csharp
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
```

### Source code:
https://github.com/Andrea-Bruno/EncryptionAlgorithm

### Demonstration and example usage from code:
https://github.com/Andrea-Bruno/EncryptionAlgorithm/blob/master/Encryption%20Usage%20Test/Program.cs

### Support against brute force attacks
Protection against brute force attacks has been implemented using open source algorithms that can be inspected by academics and cryptography experts
Source code of protection against brute force attacks: https://github.com/Andrea-Bruno/AntiBruteForce
