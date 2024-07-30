using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignatures
{
	internal class DigitalSignature
	{
		private RSAParameters _publicKey;
		private RSAParameters _privateKey;
		internal void AssignNewKey(int keySize)
		{
			using (var rsa = new RSACryptoServiceProvider(keySize))
			{
				rsa.PersistKeyInCsp = false;
				_publicKey = rsa.ExportParameters(false); // create public key
				_privateKey = rsa.ExportParameters(true); // creates privat key
			}
		}

		private byte[] SignData(byte[] hashOFDataToSign)
		{
			using (var rsa = new RSACryptoServiceProvider())
			{
				rsa.PersistKeyInCsp = false;
				rsa.ImportParameters(_privateKey);
				var rsaformatter = new RSAPKCS1SignatureFormatter(rsa);
				rsaformatter.SetHashAlgorithm("SHA256");

				return rsaformatter.CreateSignature(hashOFDataToSign);
			}

		}

		private bool verifySignature(byte[] hashOFDataToSign, byte[] signature)
		{
			using (var rsa = new RSACryptoServiceProvider())
			{
				rsa.ImportParameters(_publicKey);
				var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
				rsaDeformatter.SetHashAlgorithm("SHA256");

				return rsaDeformatter.VerifySignature(hashOFDataToSign, signature);
			}

		}

		internal void SignAndVerifyData()
		{
			Console.WriteLine();
			Console.WriteLine("Demonstarting Signature and Verification of Signature");
			var document = Encoding.UTF8.GetBytes("Document To Sign");
			byte[] hashedDocument;

			using (var sha256 = SHA256.Create())
			{
				hashedDocument = sha256.ComputeHash(document);
			}

			var digitalsignature = new DigitalSignature();
			digitalsignature.AssignNewKey(2048);

			var signature = digitalsignature.SignData(hashedDocument);
			var verified = digitalsignature.verifySignature(hashedDocument, signature);


			Console.WriteLine("Organal Text : " + Encoding.UTF8.GetString(document));
			Console.WriteLine("hashed document : " + Convert.ToBase64String(hashedDocument));
			Console.WriteLine("digital signature : " + Convert.ToBase64String(signature));
			Console.WriteLine("signature verified  : " + verified);
			Console.WriteLine();

		}
	}
}
