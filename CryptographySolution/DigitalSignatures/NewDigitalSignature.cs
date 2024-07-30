using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures
{
	internal class NewDigitalSignature
	{
		private RSA rsa;

        public NewDigitalSignature()
        {
				rsa = RSA.Create(2048);
        }
		private byte[] ComputeHashSha256(byte[] toBeHashed) 
		{
			using (var sha256 = SHA256.Create())
			{
				return sha256.ComputeHash(toBeHashed);
			}
		
		}

		private (byte[],byte[]) SignData(byte[] DataToSign)
		{
			byte[] hashOfDataToSign = ComputeHashSha256(DataToSign);
			return (rsa.SignHash(hashOfDataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), hashOfDataToSign);
		}

		private bool verifySignature(byte[] signature, byte[] hashOFDataToSign )
		{
			return rsa.VerifyHash(hashOFDataToSign, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

		}

		private byte[] ExportPrivateKey(int NumberOfItertaions, string Password)
		{
			byte[] encryptedPrivateKey = new byte[2000];
			PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, NumberOfItertaions);
			var arrayspan = new Span<byte>(encryptedPrivateKey);
			rsa.TryExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(Password), keyParams, arrayspan, out _);

			return encryptedPrivateKey;
		}

		private void ImportEncryptedPrivateKey(byte[] encryptedKey, string password)
		{
			rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
		}

		private byte[] ExportPublicKey()
		{
			return rsa.ExportRSAPublicKey();
		}

		private void ImportPublicKey(byte[] publicKey)
		{
			rsa.ImportRSAPublicKey(publicKey, out _);
		}



		internal void SignAndVerifyData()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting Signature and Verification of Signature with Key");
			var document = Encoding.UTF8.GetBytes("Document To Sign");
			var digitalsignature = new NewDigitalSignature();

			var signature = digitalsignature.SignData(document);
			var verified = digitalsignature.verifySignature(signature.Item1, signature.Item2);
			
			Console.WriteLine("Organal Text : " + Encoding.UTF8.GetString(document));
			Console.WriteLine("signature verified  : " + verified);
			Console.WriteLine();

		}


		internal void SignAndVerifyDataWithKey()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting NEW RSA Encryption and DeCryption with key export");
			string password = "someStongPassword";

			var digitalSignature = new NewDigitalSignature();
			var encryptedPrivateKey = digitalSignature.ExportPrivateKey(10000, password);
			var publicKey = digitalSignature.ExportPublicKey();

			var document = Encoding.UTF8.GetBytes("Document To Sign");

			var digitalSignature2 = new NewDigitalSignature();
			digitalSignature2.ImportPublicKey(publicKey);
			digitalSignature2.ImportEncryptedPrivateKey(encryptedPrivateKey, password);
			var signature = digitalSignature2.SignData(document);
			var verified = digitalSignature2.verifySignature(signature.Item1, signature.Item2);

			Console.WriteLine("Organal Text : " + Encoding.UTF8.GetString(document));
			Console.WriteLine("signature verified: " + verified);
			Console.WriteLine();

		}
	}
}
