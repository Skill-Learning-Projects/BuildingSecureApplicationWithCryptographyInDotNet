using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EnCryptionDecryption
{
	//ASymmetric Encryption and Decryption
	internal class NewRSA
	{
		private RSA _rsa;
		public NewRSA()
		{
			_rsa = RSA.Create(2048);
		}

		private byte[] Encrypt(string dataToEncrypt)
		{
			return _rsa.Encrypt(Encoding.UTF8.GetBytes(dataToEncrypt), RSAEncryptionPadding.OaepSHA256);
		}

		private byte[] Encrypt(byte[] dataToEncrypt)
		{
			return _rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
		}

		private byte[] Decrypt(byte[] dataToDecrypt)
		{
			return _rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
		}

		private byte[] ExportPrivateKey(int NumberOfItertaions, string Password)
		{
			byte[] encryptedPrivateKey = new byte[2000];
			PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, NumberOfItertaions);
			var arrayspan = new Span<byte>(encryptedPrivateKey);
			_rsa.TryExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(Password), keyParams, arrayspan, out _);

			return encryptedPrivateKey;
		}

		private void ImportEncryptedPrivateKey(byte[] encryptedKey, string password)
		{
			_rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
		}

		private byte[] ExportPublicKey()
		{
			return _rsa.ExportRSAPublicKey();
		}

		private void ImportPublicKey(byte[] publicKey)
		{
			 _rsa.ImportRSAPublicKey(publicKey, out _);
		}

		internal void NewRSAEncryptDecrypt()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting NEW RSA Encryption and DeCryption");
			//const string conatinerName = "MyContainer";
			const string orignal_text = "Mary had a little lamp.";
			var rsa = new NewRSA();

			var encryptedRsa = rsa.Encrypt(Encoding.UTF8.GetBytes(orignal_text));
			var decryptedRsaP = rsa.Decrypt(encryptedRsa);

			Console.WriteLine("Organal Text : " + orignal_text);
			Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encryptedRsa));
			Console.WriteLine("DeEncrypted Text : " + Encoding.UTF8.GetString(decryptedRsaP));
			Console.WriteLine();
		}

		internal void NewRSAEncryptDecryptWithKeyExport()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting NEW RSA Encryption and DeCryption with key export");

			const string orignal_text = "Mary had a little lamp.";
			string password = "someStongPassword";
			
			var rsa = new NewRSA();
			var encryptedPrivateKey = rsa.ExportPrivateKey(10000, password);
			var publicKey = rsa.ExportPublicKey();
			var encrypted = rsa.Encrypt(orignal_text);

			var rsa2 = new NewRSA();
			rsa2.ImportPublicKey(publicKey);
			rsa2.ImportEncryptedPrivateKey(encryptedPrivateKey, password);
			var decrypted = rsa2.Decrypt(encrypted);

			Console.WriteLine("Organal Text : " + orignal_text);
			Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encrypted));
			Console.WriteLine("DeEncrypted Text : " + Encoding.UTF8.GetString(decrypted));
			Console.WriteLine();
		}
	}
}
