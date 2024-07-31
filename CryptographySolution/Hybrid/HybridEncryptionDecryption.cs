using RandomNumberGenerator;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Hybrid.EncryptionDecryption
{
	internal class HybridEncryptionDecryption
	{
		internal void DemonstarteHybridEncryptionDecryption()
		{
			Console.WriteLine("Demonstarting Hybrid Encryption and Decryption");
			const string original = "Very secret and important information that can not fall into the wrong hands.";

			var rsaParams = new RSAWithRSAParameterKey();
			rsaParams.AssignNewKey();

			var hybrid = new HybridEncryption();

			var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
			var decrpyted = hybrid.DecryptData(encryptedBlock, rsaParams);

			Console.WriteLine("Hybrid Encryption Demonstration in .NET");
			Console.WriteLine("---------------------------------------");
			Console.WriteLine();
			Console.WriteLine("Original Message = " + original);
			Console.WriteLine();
			Console.WriteLine("Message After Decryption = " + Encoding.UTF8.GetString(decrpyted));
		}

	}

	internal class EncryptedPacket
	{
		public byte[] EncryptedSessionKey;
		public byte[] EncryptedData;
		public byte[] Iv;
	}

	internal class AesEncryption
	{
		internal byte[] GenerateRandomNumber(int length)
		{
			return RandomNumGen.GenerateRandomNumber(length);
		}

		internal byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
		{
			using (var aes = new AesCryptoServiceProvider())
			{
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				aes.Key = key;
				aes.IV = iv;

				using (var memoryStream = new MemoryStream())
				{
					var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(),
						CryptoStreamMode.Write);

					cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
					cryptoStream.FlushFinalBlock();

					return memoryStream.ToArray();
				}
			}
		}

		internal byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
		{
			using (var aes = new AesCryptoServiceProvider())
			{
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				aes.Key = key;
				aes.IV = iv;

				using (var memoryStream = new MemoryStream())
				{
					var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(),
						CryptoStreamMode.Write);

					cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
					cryptoStream.FlushFinalBlock();

					var decryptBytes = memoryStream.ToArray();

					return decryptBytes;
				}
			}
		}
	}

	

	internal class HybridEncryption
	{
		private readonly AesEncryption _aes = new AesEncryption();

		internal EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
		{
			// Generate our session key.
			var sessionKey = _aes.GenerateRandomNumber(32);

			// Create the encrypted packet and generate the IV.
			var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(16) };

			// Encrypt our data with AES.
			encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);

			// Encrypt the session key with RSA
			encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

			return encryptedPacket;
		}

		internal byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
		{
			// Decrypt AES Key with RSA.
			var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);

			// Decrypt our data with  AES using the decrypted session key.
			var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData,
											 decryptedSessionKey, encryptedPacket.Iv);

			return decryptedData;
		}
	}


	internal class RSAWithRSAParameterKey
	{
		private RSAParameters _publicKey;
		private RSAParameters _privateKey;

		internal void AssignNewKey()
		{
			using (var rsa = new RSACryptoServiceProvider(2048))
			{
				rsa.PersistKeyInCsp = false;
				_publicKey = rsa.ExportParameters(false);
				_privateKey = rsa.ExportParameters(true);
			}
		}

		internal byte[] EncryptData(byte[] dataToEncrypt)
		{
			byte[] cipherbytes;

			using (var rsa = new RSACryptoServiceProvider())
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_publicKey);

				cipherbytes = rsa.Encrypt(dataToEncrypt, true);
			}

			return cipherbytes;
		}

		internal byte[] DecryptData(byte[] dataToEncrypt)
		{
			byte[] plain;

			using (var rsa = new RSACryptoServiceProvider())
			{
				rsa.PersistKeyInCsp = false;

				rsa.ImportParameters(_privateKey);
				plain = rsa.Decrypt(dataToEncrypt, true);
			}

			return plain;
		}
	}

}
