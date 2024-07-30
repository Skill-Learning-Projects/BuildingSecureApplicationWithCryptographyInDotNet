
using System.Text;

namespace EnCryptionDecryption
{
	internal class Program
	{
		static void Main(string[] args)
		{

			Console.WriteLine("Demonstrating Encryption and Decryption AES");

			const string _orignalText = "Same text for ecryption decrption";
			var _aes = new AES();
			var _key = _aes.GenerateRandomKey(32);
			var _iv = _aes.GenerateRandomKey(16);

			var _encrypted = _aes.Encrypt(Encoding.UTF8.GetBytes(_orignalText), _key, _iv);
			var _decrypted = _aes.Decrypt(_encrypted, _key, _iv);

			Console.WriteLine("Orignal Text : " + _orignalText);
			Console.WriteLine("Key : " + Convert.ToBase64String(_key));
			Console.WriteLine("iv : " + Convert.ToBase64String(_iv));
			Console.WriteLine("encrypted text : " + Convert.ToBase64String(_encrypted));
			Console.WriteLine("decrypted text : " + Encoding.UTF8.GetString(_decrypted));


			Console.WriteLine();
			Console.WriteLine("Demonstrating Encryption and Decryption DES");
			var _des = new DES();
			var _key_des = _des.GenerateRandomKey(8);
			var _iv_des = _des.GenerateRandomKey(8);
			var _encrypted_des = _des.Encrypt(Encoding.UTF8.GetBytes(_orignalText), _key_des, _iv_des);
			var _decrypted_des = _des.Decrypt(_encrypted_des, _key_des, _iv_des);
			Console.WriteLine("Orignal Text : " + _orignalText);
			Console.WriteLine("Key : " + Convert.ToBase64String(_key_des));
			Console.WriteLine("iv : " + Convert.ToBase64String(_iv_des));
			Console.WriteLine("encrypted text : " + Convert.ToBase64String(_encrypted_des));
			Console.WriteLine("decrypted text : " + Encoding.UTF8.GetString(_decrypted_des));


			Console.WriteLine();
			Console.WriteLine("Demonstrating Encryption and Decryption Triple DES");
			var _tdes = new TripleDES();
			//var _key_tdes = _tdes.GenerateRandomKey(16); // this will conatin two keys as one key is of 8 bytes
			var _key_tdes3 = _tdes.GenerateRandomKey(24); // this will conatin three keys as one key is of 8 bytes

			var _iv_tdes = _tdes.GenerateRandomKey(8);
			var _encrypted_tdes = _tdes.Encrypt(Encoding.UTF8.GetBytes(_orignalText), _key_tdes3, _iv_tdes);
			var _decrypted_tdes = _tdes.Decrypt(_encrypted_tdes, _key_tdes3, _iv_tdes);
			Console.WriteLine("Orignal Text : " + _orignalText);
			Console.WriteLine("Key : " + Convert.ToBase64String(_key_tdes3));
			Console.WriteLine("iv : " + Convert.ToBase64String(_iv_tdes));
			Console.WriteLine("encrypted text : " + Convert.ToBase64String(_encrypted_tdes));
			Console.WriteLine("decrypted text : " + Encoding.UTF8.GetString(_decrypted_tdes));


			Console.WriteLine();
			Console.WriteLine("Demonstrating Encryption and Decryption AES-GCM");
			var _metadata = "some metadata";
			var _aesgcm = new AESGCME();
			var _aesgcm_key = _tdes.GenerateRandomKey(32);
			var _aesgcm_nonce = _tdes.GenerateRandomKey(12);

			(byte[] ciphertext, byte[] tag) _encrypted_aesgcm = _aesgcm.Encrypt(Encoding.UTF8.GetBytes(_orignalText), _aesgcm_key, _aesgcm_nonce, Encoding.UTF8.GetBytes(_metadata));
			var _decrypted_aesgcm = _aesgcm.Decrypt(_encrypted_aesgcm.ciphertext, _aesgcm_key, _aesgcm_nonce, _encrypted_aesgcm.tag, Encoding.UTF8.GetBytes(_metadata));
			Console.WriteLine("Orignal Text : " + _orignalText);
			Console.WriteLine("Key: " + Convert.ToBase64String(_aesgcm_key));
			Console.WriteLine("Nonce : " + Convert.ToBase64String(_aesgcm_nonce));
			Console.WriteLine("encrpted CipherText : " + Convert.ToBase64String(_encrypted_aesgcm.ciphertext));
			Console.WriteLine("encrypted tag : " + Convert.ToBase64String(_encrypted_aesgcm.tag));

			Console.WriteLine("decrypted text : " + Encoding.UTF8.GetString(_decrypted_aesgcm));




			Console.ReadLine();
		}
	}
}
