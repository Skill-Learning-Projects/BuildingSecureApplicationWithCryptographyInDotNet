using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EnCryptionDecryption
{
	//ASymmetric Encryption and Decryption
	internal class RSAWithCSPKey
	{
		const string conatinerName = "MyContainer";
		const string providerName = "Microsoft Strong Cryptographic Provider"; // this should be used as is, becasue its windows service provider whcih lets you store encryption keys in a container

		internal void AssignNewKey()
		{
			var cspParameter = new CspParameters(1)
			{
				KeyContainerName = conatinerName,
				Flags =CspProviderFlags.UseMachineKeyStore,
				ProviderName = providerName
			};

			var rsa = new RSACryptoServiceProvider(cspParameter)
			{
				PersistKeyInCsp = true
			};

		}

		internal void DeleteKeyInCSP()
		{
			var cspParams = new CspParameters { KeyContainerName = conatinerName };
			var rsa = new RSACryptoServiceProvider(cspParams) { PersistKeyInCsp=false };
			rsa.Clear();
		}

		internal byte[] EncryptData(byte[] dataToEncrypt)
		{
			byte[] cipherbytes;
			var cspParams = new CspParameters { KeyContainerName = conatinerName};
			using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
			{
				cipherbytes = rsa.Encrypt(dataToEncrypt, false);
			}

			return cipherbytes;
		}

		internal byte[] DecryptData(byte[] dataToDecrypt)
		{
			byte[] plain;
			var cspParams = new CspParameters { KeyContainerName = conatinerName };
			using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
			{
				plain = rsa.Decrypt(dataToDecrypt, false);
			}

			return plain;
		}

		internal void RSAWithRSACSPKey()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting RSA With CSP based Key Encryption and DeCryption");
			//const string conatinerName = "MyContainer";
			const string orignal_text = "Mary had a little lamp.";
			var rsaCSP = new RSAWithCSPKey();
			rsaCSP.AssignNewKey();

			var encryptedRsaCSP = rsaCSP.EncryptData(Encoding.UTF8.GetBytes(orignal_text));
			var decryptedRsaCSP = rsaCSP.DecryptData(encryptedRsaCSP);

			rsaCSP.DeleteKeyInCSP();

			Console.WriteLine("Organal Text : " + orignal_text);
			Console.WriteLine("Encrypted Text : " + Convert.ToBase64String(encryptedRsaCSP));
			Console.WriteLine("DeEncrypted Text : " + Encoding.UTF8.GetString(decryptedRsaCSP));
			Console.WriteLine();

		}


	}
}
