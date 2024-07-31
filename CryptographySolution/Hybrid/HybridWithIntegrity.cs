using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using RandomNumberGenerator;

namespace Hybrid.HybridEncryptionDecryptionWithIntegrity
{
	internal class HybridWithIntegrity
	{

		internal void DemonstarteHybridWithIntegrity()
		{
			Console.WriteLine("Demonstarting Hybrid Encryption and Decryption With Integrity");
			const string original = "Very secret and important information that can not fall into the wrong hands.";

			var hybrid = new HybridEncryption();

			var rsaParams = new RSAWithRSAParameterKey();
			rsaParams.AssignNewKey();

			Console.WriteLine("Hybrid Encryption with Integrity Check Demonstration in .NET");
			Console.WriteLine("------------------------------------------------------------");
			Console.WriteLine();

			try
			{
				var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
				var decrpyted = hybrid.DecryptData(encryptedBlock, rsaParams);

				Console.WriteLine("Original Message = " + original);
				Console.WriteLine();
				Console.WriteLine("Message After Decryption = " + Encoding.UTF8.GetString(decrpyted));
			}
			catch (CryptographicException ex)
			{
				Console.WriteLine("Error : " + ex.Message);
			}

		}

	}

	internal class EncryptedPacket
	{
		public byte[] EncryptedSessionKey;
		public byte[] EncryptedData;
		public byte[] Iv;
		public byte[] Hmac;
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
			var sessionKey = _aes.GenerateRandomNumber(32);
			var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(16) };

			// Encrypt data with AES and AES Key with RSA
			encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);
			encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

			using (var hmac = new HMACSHA256(sessionKey))
			{
				encryptedPacket.Hmac = hmac.ComputeHash(Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv));
			}

			return encryptedPacket;
		}

		internal byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
		{
			// Decrypt AES Key with RSA and then decrypt data with AES.
			var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);

			using (var hmac = new HMACSHA256(decryptedSessionKey))
			{
				var hmacToCheck = hmac.ComputeHash(Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv));

				if (!Compare(encryptedPacket.Hmac, hmacToCheck))
				{
					throw new CryptographicException("HMAC for decryption does not match encrypted packet.");
				}
			}

			var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);

			return decryptedData;
		}

		private static byte[] Combine(byte[] first, byte[] second)
		{
			var ret = new byte[first.Length + second.Length];

			Buffer.BlockCopy(first, 0, ret, 0, first.Length);
			Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

			return ret;
		}

		private static bool Compare(byte[] array1, byte[] array2)
		{
			var result = array1.Length == array2.Length;

			for (var i = 0; i < array1.Length && i < array2.Length; ++i)
			{
				result &= array1[i] == array2[i];
			}

			return result;
		}

		// Don't use this method for comparing byte arrays.
		// It is left here as an example.
		private static bool CompareUnSecure(byte[] array1, byte[] array2)
		{
			if (array1.Length != array2.Length)
			{
				return false;
			}

			for (int i = 0; i < array1.Length; ++i)
			{
				if (array1[i] != array2[i])
				{
					return false;
				}
			}

			return true;
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
