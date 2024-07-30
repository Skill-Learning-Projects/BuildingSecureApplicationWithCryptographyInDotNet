using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EnCryptionDecryption
{
	//ASymmetric Encryption and Decryption
	internal class RSAWithParameterKey
	{
		private RSAParameters _publicKey;
		private RSAParameters _privateKey;
		internal void AssignNewKey(int keySize)
		{
			using (var rsa = new RSACryptoServiceProvider(keySize))
			{
				rsa.PersistKeyInCsp = false;
				_publicKey =rsa.ExportParameters(false); // create public key
				_privateKey =rsa.ExportParameters(true); // creates privat key
			}
		}

		private byte[] EncryptData(byte[] dataToEncrypt)
		{
			byte[] cipherytes;
			// no need to specify key size in constructor when importing a key
			using (var rsa = new RSACryptoServiceProvider())
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_publicKey);
				cipherytes = rsa.Encrypt(dataToEncrypt, true);
			}

			return cipherytes;
		}

		private byte[] DecryptData(byte[] dataToDecrypt)
		{
			byte[] plain;
			// no need to specify key size in constructor when importing a key
			using (var rsa = new RSACryptoServiceProvider())
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_privateKey);
				plain = rsa.Decrypt(dataToDecrypt, true);
			}

			return plain;
		}

		internal void RSAWithRSAKeyParameters()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting RSA with Key Encryption and DeCryption");
			//const string conatinerName = "MyContainer";
			const string orignal_text = "Mary had a little lamp.";
			var rsaParams = new RSAWithParameterKey();
			rsaParams.AssignNewKey(2048);

			var encryptedRsaParameters = rsaParams.EncryptData(Encoding.UTF8.GetBytes(orignal_text));
			var decryptedRsaParameters = rsaParams.DecryptData(encryptedRsaParameters);

			Console.WriteLine("Organal Text : " + orignal_text);
			Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encryptedRsaParameters));
			Console.WriteLine("DeEncrypted Text : " + Encoding.UTF8.GetString(decryptedRsaParameters));
			Console.WriteLine();

		}
	}
}
