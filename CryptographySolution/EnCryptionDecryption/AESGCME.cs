using RandomNumberGenerator;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace EnCryptionDecryption
{
	internal class AESGCME
	{
		internal byte[] GenerateRandomKey(int KeySize)
		{
			return RandomNumGen.GenerateRandomNumber(KeySize);
		}


		internal (byte[], byte[]) Encrypt(byte[] datatToEncrypt, byte[] key, byte[] nonce, byte[] associatedData)
		{
			byte[] tag = new byte[16];
			byte[] cipherText = new byte[datatToEncrypt.Length];

			using (var _aesGCM = new AesGcm(key))
			{
				_aesGCM.Encrypt(nonce, datatToEncrypt, cipherText, tag, associatedData);
			}
			return (cipherText, tag);
		}


		internal byte[] Decrypt(byte[] cipherText, byte[] key, byte[] nonce, byte[] tag, byte[] associatedData)
		{
			byte[] decryptedData = new byte[cipherText.Length];
			using (var _aesGCM = new AesGcm(key))
			{
				_aesGCM.Decrypt(nonce, cipherText, tag, decryptedData, associatedData);

			}
			return decryptedData;
		}

	}
}
