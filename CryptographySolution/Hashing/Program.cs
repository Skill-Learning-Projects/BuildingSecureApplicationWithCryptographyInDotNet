using System.Text;
namespace Hashing
{
	internal class Program
	{
		static void Main(string[] args)
		{
			const string _orignalMessage1 = "Origanl Message to be Hashed 1";
			const string _orignalMessage2 = "Origanl Message to be Hashed 2";

			Console.WriteLine("Demonstarting Hashing in .Net");
			Console.WriteLine("-----------------------------");
			Console.WriteLine("Origanl Message 1 : " + _orignalMessage1);
			Console.WriteLine("Orignal Message 2 : " + _orignalMessage2);


			var sha1_HashedMessage1 = Hashing.ComputeHashSha1(Encoding.UTF8.GetBytes(_orignalMessage1));
			var sha1_HashedMessage2 = Hashing.ComputeHashSha1(Encoding.UTF8.GetBytes(_orignalMessage2));

			var sha256_HashedMessage1 = Hashing.ComputeHashSha256(Encoding.UTF8.GetBytes(_orignalMessage1));
			var sha256_HashedMessage2 = Hashing.ComputeHashSha256(Encoding.UTF8.GetBytes(_orignalMessage2));

			var sha512_HashedMessage1 = Hashing.ComputeHashSha512(Encoding.UTF8.GetBytes(_orignalMessage1));
			var sha512_HashedMessage2 = Hashing.ComputeHashSha512(Encoding.UTF8.GetBytes(_orignalMessage2));

			var md5_HashedMessage1 = Hashing.ComputeHashMD5(Encoding.UTF8.GetBytes(_orignalMessage1));
			var md5_HashedMessage2 = Hashing.ComputeHashMD5(Encoding.UTF8.GetBytes(_orignalMessage2));

			//or you cna use UTF8Encoding directly
			//var md5_HashedMessage2 = Hashing.ComputeHashMD5(UTF8Encoding.UTF8.GetBytes(_orignalMessage2));



			Console.WriteLine("Sha1 Hashing");
			Console.WriteLine("Sha1 Message1 Hash : " + Convert.ToBase64String(sha1_HashedMessage1));
			Console.WriteLine("Sha1 Message2 Hash : " + Convert.ToBase64String(sha1_HashedMessage2));

			Console.WriteLine("Sha256 Hashing");
			Console.WriteLine("Sha256 Message1 Hash : " + Convert.ToBase64String(sha256_HashedMessage1));
			Console.WriteLine("Sha256 Message2 Hash : " + Convert.ToBase64String(sha256_HashedMessage2));

			Console.WriteLine("Sha512 Hashing");
			Console.WriteLine("Sha512 Message1 Hash : " + Convert.ToBase64String(sha512_HashedMessage1));
			Console.WriteLine("Sha512 Message2 Hash : " + Convert.ToBase64String(sha512_HashedMessage2));

			Console.WriteLine("ShaMD5 Hashing");
			Console.WriteLine("ShaMD5 Message1 Hash : " + Convert.ToBase64String(md5_HashedMessage1));
			Console.WriteLine("ShaMD5 Message2 Hash : " + Convert.ToBase64String(md5_HashedMessage2));

			Console.WriteLine("********************************************************************************************");
			Console.WriteLine("HMAC hashing demondstartced below");

			Console.WriteLine($".NET Version: {System.Environment.Version}");

			var _hmac_key = HMAC.GenerateRandomKey(32);

			Console.WriteLine("Orignal Message 1 : " + _orignalMessage1 + " | Orignal Message 2 : " + _orignalMessage2);
			Console.WriteLine("HMAC KEY for all encrytions is : " + Convert.ToBase64String(_hmac_key));

			var _HMACSHA1_message1 = HMAC.Compute_HMACSHA1(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			var _HMACSHA1_message2 = HMAC.Compute_HMACSHA1(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			Console.WriteLine("_HMACSHA1_message1 : " + Convert.ToBase64String(_HMACSHA1_message1));
			Console.WriteLine("_HMACSHA1_message2 : " + Convert.ToBase64String(_HMACSHA1_message2));

			var _HMACSHA256_message1 = HMAC.Compute_HMACSHA256(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			var _HMACSHA256_message2 = HMAC.Compute_HMACSHA256(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			Console.WriteLine("_HMACSHA256_message1 : " + Convert.ToBase64String(_HMACSHA256_message1));
			Console.WriteLine("_HMACSHA256_message2 : " + Convert.ToBase64String(_HMACSHA256_message2));
			//below code will throw error becaseu HMACSHA3_256 is not supported on my machine but if its supported the this the way to use it
			//var _HMACSHA3_256_message1 = HMAC.Compute_HMACSHA3_256(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			//var _HMACSHA3_256_message2 = HMAC.Compute_HMACSHA3_256(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			//Console.WriteLine("_HMACSHA3_256_message1 : " + Convert.ToBase64String(_HMACSHA3_256_message1));
			//Console.WriteLine("_HMACSHA3_256_message2 : " + Convert.ToBase64String(_HMACSHA3_256_message2));

			var _HMACSHA512_message1 = HMAC.Compute_HMACSHA512(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			var _HMACSHA512_message2 = HMAC.Compute_HMACSHA512(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			Console.WriteLine("_HMACSHA512_message1 : " + Convert.ToBase64String(_HMACSHA512_message1));
			Console.WriteLine("_HMACSHA512_message2 : " + Convert.ToBase64String(_HMACSHA512_message2));
			//below code will throw error becaseu HMACSHA3_512 is not supported on my machine but if its supported the this the way to use it
			//var _HMACSHA3_512_message1 = HMAC.Compute_HMACSHA3_512(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			//var _HMACSHA3_512_message2 = HMAC.Compute_HMACSHA3_512(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			//Console.WriteLine("_HMACSHA3_512_message1 : " + Convert.ToBase64String(_HMACSHA3_512_message1));
			//Console.WriteLine("_HMACSHA3_512_message2 : " + Convert.ToBase64String(_HMACSHA3_512_message2));


			var _HMACSHA384_message1 = HMAC.Compute_HMACSHA384(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			var _HMACSHA384_message2 = HMAC.Compute_HMACSHA384(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			Console.WriteLine("_HMACSHA384_message1 : " + Convert.ToBase64String(_HMACSHA384_message1));
			Console.WriteLine("_HMACSHA384_message2 : " + Convert.ToBase64String(_HMACSHA384_message2));
			////below code will throw error becaseu HMACSHA3_384 is not supported on my machine but if its supported the this the way to use it
			//var _HMACSHA3_384_message1 = HMAC.Compute_HMACSHA3_384(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			//var _HMACSHA3_384_message2 = HMAC.Compute_HMACSHA3_384(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			//Console.WriteLine("_HMACSHA3_384_message1 : " + Convert.ToBase64String(_HMACSHA3_384_message1));
			//Console.WriteLine("_HMACSHA3_384_message2 : " + Convert.ToBase64String(_HMACSHA3_384_message2));

			var _HMACMD5_message1 = HMAC.Compute_HMACMD5(Encoding.UTF8.GetBytes(_orignalMessage1), _hmac_key);
			var _HMACMD5_message2 = HMAC.Compute_HMACMD5(Encoding.UTF8.GetBytes(_orignalMessage2), _hmac_key);
			Console.WriteLine("_HMACMD5_message1 : " + Convert.ToBase64String(_HMACMD5_message1));
			Console.WriteLine("_HMACMD5_message2 : " + Convert.ToBase64String(_HMACMD5_message2));


			//becasue SHA3 is not supported on my current version of Windows machine
			//that why we can also use 3rd party packages to do encryption of SHA3
			//using SHA3.Net a 3rd party libray to create SHA3 hashes 
			Console.WriteLine("CREATING HASHING USING 3RD PARTY PACKAGE SHA3.NET");
			var _SHA3Net_256_message1 = HMAC_SHA3.Compute_SHA3_256(Encoding.UTF8.GetBytes(_orignalMessage1));
			var _SHA3Net_256_message2 = HMAC_SHA3.Compute_SHA3_256(Encoding.UTF8.GetBytes(_orignalMessage2));
			Console.WriteLine("_SHA3Net_256_message1 : " + Convert.ToBase64String(_SHA3Net_256_message1));
			Console.WriteLine("_SHA3Net_256_message2 : " + Convert.ToBase64String(_SHA3Net_256_message2));

			var _SHA3Net_244_message1 = HMAC_SHA3.Compute_SHA3_224(Encoding.UTF8.GetBytes(_orignalMessage1));
			var _SHA3Net_244_message2 = HMAC_SHA3.Compute_SHA3_224(Encoding.UTF8.GetBytes(_orignalMessage2));
			Console.WriteLine("_SHA3Net_244_message1 : " + Convert.ToBase64String(_SHA3Net_244_message1));
			Console.WriteLine("_SHA3Net_244_message2 : " + Convert.ToBase64String(_SHA3Net_244_message2));

			var _SHA3Net_512_message1 = HMAC_SHA3.Compute_SHA3_512(Encoding.UTF8.GetBytes(_orignalMessage1));
			var _SHA3Net_512_message2 = HMAC_SHA3.Compute_SHA3_512(Encoding.UTF8.GetBytes(_orignalMessage2));
			Console.WriteLine("_SHA3Net_512_message1 : " + Convert.ToBase64String(_SHA3Net_512_message1));
			Console.WriteLine("_SHA3Net_512_message2 : " + Convert.ToBase64String(_SHA3Net_512_message2));

			var _SHA3Net_384_message1 = HMAC_SHA3.Compute_SHA3_384(Encoding.UTF8.GetBytes(_orignalMessage1));
			var _SHA3Net_384_message2 = HMAC_SHA3.Compute_SHA3_384(Encoding.UTF8.GetBytes(_orignalMessage2));
			Console.WriteLine("_SHA3Net_384_message1 : " + Convert.ToBase64String(_SHA3Net_384_message1));
			Console.WriteLine("_SHA3Net_384_message2 : " + Convert.ToBase64String(_SHA3Net_384_message2));


			// WE CAN ALSO USE OTHER 3RD PARTY LIBRARIES FOR HASHING AS GIVEN BELOW
			//1. Bouncy Castle (.NET Standard/Framework Support)
			//2. Sodium.Core (Modern .NET, libsodium Bindings)


			Console.WriteLine("Demonstrating PBKDF = Password Based Key Derivation Functions");

			var _passwordToHash = "VeryComplexPassword";
			PBKDF2.HashPasswordWithSalt(_passwordToHash, 100); //will hash password 100 times
			PBKDF2.HashPasswordWithSalt(_passwordToHash, 1000); //will hash password 1000 times
			PBKDF2.HashPasswordWithSalt(_passwordToHash, 10000); //will hash password 10000 times
			PBKDF2.HashPasswordWithSalt(_passwordToHash, 100000); //will hash password 100000 times

			PBKDF2.HashPasswordWithSalt(_passwordToHash);

			Console.ReadLine();

		}
	}
}
