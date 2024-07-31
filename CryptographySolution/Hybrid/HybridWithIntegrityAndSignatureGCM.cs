using RandomNumberGenerator;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hybrid.WithIntegrityAndSignatureGCM
{
	internal class HybridWithIntegrityAndSignatureGCM
	{
		public void DemonstrateHybridWithIntegrityAndSignatureGCM()
		{
			Console.WriteLine("Demonstarting Hybrid Encryption and Decryption With Integrity and Signature GCM");
			const string original = "Very secret and important information that can not fall into the wrong hands.";

			var hybrid = new HybridEncryption();

			var rsaParams = new NewRSA();

			var digitalSignature = new NewDigitalSignature();

			Console.WriteLine("Hybrid Encryption with Integrity Check and Digital Signature Demonstration in .NET");
			Console.WriteLine("----------------------------------------------------------------------------------");
			Console.WriteLine();

			try
			{
				var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams,
														digitalSignature);

				var decrpyted = hybrid.DecryptData(encryptedBlock, rsaParams, digitalSignature);

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
		public byte[] Tag;
		public byte[] SignatureHMAC;
		public byte[] Signature;
	}



	internal class AesGCMEncryption
	{
		internal byte[] GenerateRandomNumber(int length)
		{
			return RandomNumGen.GenerateRandomNumber(length);
		}

		internal (byte[], byte[]) Encrypt(byte[] dataToEncrypt, byte[] key, byte[] nonce, byte[] associatedData)
		{
			// these will be filled during the encryption
			byte[] tag = new byte[16];
			byte[] ciphertext = new byte[dataToEncrypt.Length];

			using (AesGcm aesGcm = new AesGcm(key))
			{
				aesGcm.Encrypt(nonce, dataToEncrypt, ciphertext, tag, associatedData);
			}

			return (ciphertext, tag);
		}

		internal byte[] Decrypt(byte[] cipherText, byte[] key, byte[] nonce, byte[] tag, byte[] associatedData)
		{
			byte[] decryptedData = new byte[cipherText.Length];

			using (AesGcm aesGcm = new AesGcm(key))
			{
				aesGcm.Decrypt(nonce, cipherText, tag, decryptedData, associatedData);
			}

			return decryptedData;
		}
	}


	internal class HybridEncryption
	{
		private readonly AesGCMEncryption _aes = new AesGCMEncryption();

		internal static byte[] ComputeHMACSha256(byte[] toBeHashed, byte[] hmacKey)
		{
			using (var hmacSha256 = new HMACSHA256(hmacKey))
			{
				return hmacSha256.ComputeHash(toBeHashed);
			}
		}

		internal EncryptedPacket EncryptData(byte[] original, NewRSA rsaParams,
										   NewDigitalSignature digitalSignature)
		{
			// Create AES session key.
			var sessionKey = _aes.GenerateRandomNumber(32);

			var encryptedPacket = new EncryptedPacket
			{
				Iv = _aes.GenerateRandomNumber(12)
			};

			// Encrypt data with AES-GCM
			(byte[] ciphereText, byte[] tag) encrypted =
				_aes.Encrypt(original, sessionKey, encryptedPacket.Iv, null);

			encryptedPacket.EncryptedData = encrypted.ciphereText;

			encryptedPacket.Tag = encrypted.tag;

			encryptedPacket.EncryptedSessionKey = rsaParams.Encrypt(sessionKey);

			encryptedPacket.SignatureHMAC =
				ComputeHMACSha256(
					Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv),
					sessionKey);

			encryptedPacket.Signature =
				digitalSignature.SignData(encryptedPacket.SignatureHMAC);

			return encryptedPacket;
		}

		internal byte[] DecryptData(EncryptedPacket encryptedPacket, NewRSA rsaParams,
								  NewDigitalSignature digitalSignature)
		{
			var decryptedSessionKey =
				rsaParams.Decrypt(encryptedPacket.EncryptedSessionKey);

			byte[] newHMAC = ComputeHMACSha256(
				Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv),
				decryptedSessionKey);

			if (!Compare(encryptedPacket.SignatureHMAC, newHMAC))
			{
				throw new CryptographicException(
					"HMAC for decryption does not match encrypted packet.");
			}

			if (!digitalSignature.VerifySignature(
												encryptedPacket.Signature,
												encryptedPacket.SignatureHMAC))
			{
				throw new CryptographicException(
					"Digital Signature can not be verified.");
			}

			var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData,
											 decryptedSessionKey,
											 encryptedPacket.Iv,
											 encryptedPacket.Tag,
											 null);

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
	}



	internal class NewDigitalSignature
	{
		private RSA rsa;

		public NewDigitalSignature()
		{
			rsa = RSA.Create(2048);
		}


		internal byte[] SignData(byte[] dataToSign)
		{
			return (rsa.SignHash(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
		}

		internal bool VerifySignature(byte[] signature, byte[] hashOfDataToSign)
		{
			return rsa.VerifyHash(hashOfDataToSign, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}

		internal byte[] ExportPrivateKey(int numberOfIterations, string password)
		{
			byte[] encryptedPrivateKey = new byte[2000];

			PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, numberOfIterations);
			encryptedPrivateKey = rsa.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), keyParams);

			return encryptedPrivateKey;
		}

		internal void ImportEncryptedPrivateKey(byte[] encryptedKey, string password)
		{
			rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
		}

		internal byte[] ExportPublicKey()
		{
			return rsa.ExportRSAPublicKey();
		}

		internal void ImportPublicKey(byte[] publicKey)
		{
			rsa.ImportRSAPublicKey(publicKey, out _);
		}
	}



	internal class NewRSA
	{
		private RSA rsa;

		public NewRSA()
		{
			rsa = RSA.Create(2048);
		}

		internal byte[] Encrypt(string dataToEncrypt)
		{
			return rsa.Encrypt(Encoding.UTF8.GetBytes(dataToEncrypt), RSAEncryptionPadding.OaepSHA256);
		}

		internal byte[] Encrypt(byte[] dataToEncrypt)
		{
			return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
		}

		internal byte[] Decrypt(byte[] dataToDecrypt)
		{
			return rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
		}

		internal byte[] ExportPrivateKey(int numberOfIterations, string password)
		{
			byte[] encryptedPrivateKey = new byte[2000];

			PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, numberOfIterations);
			encryptedPrivateKey = rsa.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), keyParams);

			return encryptedPrivateKey;
		}

		internal void ImportEncryptedPrivateKey(byte[] encryptedKey, string password)
		{
			rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
		}

		internal byte[] ExportPublicKey()
		{
			return rsa.ExportRSAPublicKey();
		}

		internal void ImportPublicKey(byte[] publicKey)
		{
			rsa.ImportRSAPublicKey(publicKey, out _);
		}
	}
}
