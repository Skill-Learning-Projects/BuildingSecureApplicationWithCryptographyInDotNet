using RandomNumberGenerator;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace EnCryptionDecryption
{
	//Symmetric Encryption and Decryption
	internal class TripleDES
	{
		internal byte[] GenerateRandomKey(int KeySize)
		{
			return RandomNumGen.GenerateRandomNumber(KeySize);
		}


		//This C# code performs AES encryption on the provided data (datatToEncrypt) using the given key and initialization vector (IV)
		//Important Security Considerations:
		//Key Management: The security of this encryption relies entirely on the security of the key and iv.These values must be kept secret and managed securely (e.g., using key derivation functions or a dedicated key management system).
		//Authentication: This code snippet only provides confidentiality.To ensure data integrity and authenticity, you should incorporate message authentication codes (HMACs) or digital signatures.
		internal byte[] Encrypt(byte[] datatToEncrypt, byte[] key, byte[] iv)
		{
			//AesCryptoServiceProvider: This class represents the Advanced Encryption Standard (AES) algorithm
			//implementation in .NET. It provides methods for encryption, decryption, and key generation.
			using (var _TDES = new TripleDESCryptoServiceProvider())
			{
				_TDES.Mode = CipherMode.CBC; //CipherMode.CBC: Sets the encryption mode to Cipher Block Chaining (CBC). CBC is a common mode that ensures that identical blocks of plaintext don't produce the same ciphertext, enhancing security.
				_TDES.Padding = PaddingMode.PKCS7; //PaddingMode.PKCS7: Specifies the padding scheme to use. Padding is often necessary because block cipher algorithms (like AES) operate on fixed-size blocks of data. PKCS7 is a standard padding scheme.
				_TDES.Key = key; //_AES.Key = key;: Sets the encryption key. This key should be a strong, randomly generated key that is the same length as the AES key size you want to use (e.g., 128, 192, or 256 bits).
				_TDES.IV = iv; //_AES.IV = iv;: Sets the initialization vector (IV). The IV is a random value that ensures that encrypting the same plaintext with the same key produces different ciphertext each time, further increasing security.

				//MemoryStream: Creates a memory stream to hold the encrypted data.
				using (var memorystream = new MemoryStream())
				{
					//CryptoStream: A stream that links the memory stream to the AES encryption process. It takes the memory stream, an AES encryptor object (_AES.CreateEncryptor()), and sets the mode to Write (for encryption).
					var cryptoStream = new CryptoStream(memorystream, _TDES.CreateEncryptor(), CryptoStreamMode.Write);
					//cryptoStream.Write(...): Writes the data to be encrypted (datatToEncrypt) to the CryptoStream. The CryptoStream handles encrypting the data using the configured AES settings.
					cryptoStream.Write(datatToEncrypt,0, datatToEncrypt.Length);
					//cryptoStream.FlushFinalBlock(): Ensures that any remaining data in the internal buffers is encrypted and written to the output stream.
					cryptoStream.FlushFinalBlock();
					//memorystream.ToArray(): Retrieves the encrypted data as a byte array from the memory stream.
					return memorystream.ToArray();
				}
			}

		}


		internal byte[] Decrypt(byte[] datatToDecrypt, byte[] key, byte[] iv)
		{
			using (var _TDES = new TripleDESCryptoServiceProvider())
			{

				_TDES.Mode = CipherMode.CBC;
				_TDES.Padding = PaddingMode.PKCS7;
				_TDES.Key = key;
				_TDES.IV = iv; 

				using (var memorystream = new MemoryStream())
				{
					var cryptoStream = new CryptoStream(memorystream, _TDES.CreateDecryptor(), CryptoStreamMode.Write);
					cryptoStream.Write(datatToDecrypt, 0, datatToDecrypt.Length);
					cryptoStream.FlushFinalBlock();
					return memorystream.ToArray();
				}
			}

		}

	}
}
