using RandomNumberGenerator;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace EnCryptionDecryption
{
	internal static class Protection
	{
		internal static byte[] GenerateRandomKey(int KeySize)
		{
			return RandomNumGen.GenerateRandomNumber(KeySize);
		}

		public static string Protect(string stringToProtect, string optionalEntry, DataProtectionScope scope)
		{
			byte[] encryptedData = ProtectedData.Protect(Encoding.UTF8.GetBytes(stringToProtect)
															, optionalEntry != null ? Encoding.UTF8.GetBytes(optionalEntry) : null
															, scope);
			return Convert.ToBase64String(encryptedData);
		}
		public static string UnProtect(string encryptedString, string optionalEntry, DataProtectionScope scope)
		{
			byte[] decryptedData = ProtectedData.Unprotect( Convert.FromBase64String(encryptedString)
															, optionalEntry != null ? Encoding.UTF8.GetBytes(optionalEntry) : null
															, scope);
			return Encoding.UTF8.GetString(decryptedData);
		}

		public static byte[] Protect(byte[] stringToProtect, byte[] optionalEntry, DataProtectionScope scope )
		{
			byte[] encryptedData = ProtectedData.Protect(stringToProtect 
															,optionalEntry != null ? optionalEntry : null
															,scope); 
			return encryptedData;
		}
		public static byte[] UnProtect(byte[] encryptedString, byte[] optionalEntry, DataProtectionScope scope)
		{
			byte[] decryptedData = ProtectedData.Unprotect(encryptedString
															, optionalEntry != null ? optionalEntry : null
															, scope);
			return decryptedData;
		}

		// this fucntion demonstrates the protection class functionality
		
		internal static void ProtectTestData()
		{
			Console.WriteLine("Demonstrating Protection Key");

			var dataToProtect = "Mary had a little lamp.";
			var optionalKey = "8qef5juy2389f4";
			var encrypted = Protection.Protect(dataToProtect,optionalKey, DataProtectionScope.CurrentUser);
			var decrypted = Protection.UnProtect(encrypted, optionalKey, DataProtectionScope.CurrentUser);
			Console.WriteLine("Data to Protect : " +dataToProtect +" | Optional Key : " +optionalKey);
			Console.WriteLine("encrypted data : " +encrypted );
			Console.WriteLine("decrypted data : " +decrypted);
			Console.WriteLine();
		}

		// this funciton demonstrate how to use encryption and decrption with while protecting key
		internal static void EncryptAndDecryptDataWithProtectedKey()
		{
			Console.WriteLine("Demonstrating Encrypt And Decrypt Data With Protected Key");

			var orignalData = "Mary had a little lamp.";

			var gcmkey = Protection.GenerateRandomKey(32);
			var nonce = Protection.GenerateRandomKey(12);

			//encrypt out data with AES GCM ecnyption 
			var aesgcm = new AESGCME();
			var metadata = Encoding.UTF8.GetBytes("Some MetaData");
			(byte[]encrypted, byte[]tag) result  = aesgcm.Encrypt(Encoding.UTF8.GetBytes(orignalData), gcmkey, nonce, metadata);

			//create some entropy and protect the AES Key
			var entropy = Protection.GenerateRandomKey(16);
			byte[] protectedKey = Protection.Protect(gcmkey, entropy, DataProtectionScope.CurrentUser);

			//first retrieve the key then decrypt the text using the key 
			byte[] unprotectedkey = Protection.UnProtect(protectedKey, entropy, DataProtectionScope.CurrentUser);
			var decryptedText = aesgcm.Decrypt(result.encrypted, unprotectedkey, nonce, result.tag,metadata);

			Console.WriteLine("Origanl Data : " + orignalData);
			Console.WriteLine("Key : " + Convert.ToBase64String(gcmkey));
			Console.WriteLine("Protected Key : " + Convert.ToBase64String(protectedKey));
			Console.WriteLine("UnProtected Key : " + Convert.ToBase64String(unprotectedkey));
			Console.WriteLine("Decrypted Text using key : " + Encoding.UTF8.GetString(decryptedText));
			Console.WriteLine();

		}
	}
}
