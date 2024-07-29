using RandomNumberGenerator;
using System.Security.Cryptography;


//using System.Security.Cryptography library you can generate hashing algorithems with key or wihtout key
namespace Hashing
{
	internal static class HMAC
	{
		//private const int HMAC_Keysize = 32;
		internal static byte[] GenerateRandomKey(int KeySize)
		{
			return RandomNumGen.GenerateRandomNumber(KeySize);
		}

		internal static byte[] Compute_HMACSHA1(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA1(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA1(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA1())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA256(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA256(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA256(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA256())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA3_256(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA3_256(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA3_256(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA3_256())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA512(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA512(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA512(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA512())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA3_512(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA3_512(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA3_512(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA3_512())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA384(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA384(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA384(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA384())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA3_384(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACSHA3_384(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

		internal static byte[] Compute_HMACSHA3_384(byte[] toBeHashed)
		{

			using (var _hmac = new HMACSHA3_384())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}
		internal static byte[] Compute_HMACMD5(byte[] toBeHashed, byte[] key)
		{

			using (var _hmac = new HMACMD5(key))
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}
		internal static byte[] Compute_HMACMD5(byte[] toBeHashed)
		{

			using (var _hmac = new HMACMD5())
			{
				return _hmac.ComputeHash(toBeHashed);
			}

		}

	}
}
