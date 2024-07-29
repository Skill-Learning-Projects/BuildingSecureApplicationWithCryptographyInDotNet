using RandomNumberGenerator;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

//PBKDF = Password Based Key Derivation Functions
namespace Hashing
{
	internal class PBKDF2
	{
		internal static byte[] GenerateRandomKey(int KeySize)
		{
			return RandomNumGen.GenerateRandomNumber(KeySize);
		}

		//this is the recomented method to use for hashing password
		internal static byte[] HashPassword(byte[] toBeHahed, byte[] salt, int numberOfRounds)
		{
			using (var rfc2898 = new Rfc2898DeriveBytes(toBeHahed, salt, numberOfRounds))
			{
				// it will return 20 bytes as Rfc2898DeriveBytes internally uses SHA1 which creates 20 bytes of Hash
				return rfc2898.GetBytes(20);
			}

		}

		//this is the commenly used password hashing method
		public static byte[] HashPassword(byte[] toBeHashed, byte[] salt)
		{
			var combinedhash = CombineHashes(toBeHashed, salt);

			//calling an existing hashing method to hash the bytes 
			return Hashing.ComputeHashSha256(combinedhash);
		}

		internal static void HashPasswordWithSalt(string passwordToBeHashed, int iterations)
		{
			var _salt = PBKDF2.GenerateRandomKey(32);
			var stopwatch = new Stopwatch();
			stopwatch.Start();
			// number of iteration it will do for hashing password 
			// the more the interation the secure the hash but it will take longer time
			var _hashedpassword = PBKDF2.HashPassword(Encoding.UTF8.GetBytes(passwordToBeHashed), _salt, iterations);
			stopwatch.Stop();
			Console.WriteLine();
			Console.WriteLine("passwordToBeHashed : " + passwordToBeHashed + " | SaltKey : " + Convert.ToBase64String(_salt));
			Console.WriteLine("Iteration : " + iterations + " | Time Taken : " + stopwatch.ElapsedMilliseconds + "ms | HashedPassword : " + Convert.ToBase64String(_hashedpassword));
		}

		internal static void HashPasswordWithSalt(string passwordToBeHashed)
		{
			var _salt = PBKDF2.GenerateRandomKey(32);
			var _hashedpassword = PBKDF2.HashPassword(Encoding.UTF8.GetBytes(passwordToBeHashed), _salt);
			Console.WriteLine();
			Console.WriteLine("Commonly used Hashing password method");
			Console.WriteLine("passwordToBeHashed : " + passwordToBeHashed + " | SaltKey : " + Convert.ToBase64String(_salt));
			Console.WriteLine("HashedPassword : " + Convert.ToBase64String(_hashedpassword));
		}

		// this fucntion combines two hashes into single hash
		private static byte[] CombineHashes(byte[] first, byte[] second)
		{
			var returnhash = new byte[first.Length + second.Length];
			Buffer.BlockCopy(first, 0, returnhash, 0, first.Length);
			Buffer.BlockCopy(second, 0, returnhash, first.Length, second.Length);
			return returnhash;

		}

	}
}
