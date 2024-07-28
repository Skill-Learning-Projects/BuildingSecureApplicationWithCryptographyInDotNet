using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using RandomNumberGenerator;
using SHA3.Net;

namespace Hashing
{
	internal static class HMAC_SHA3
	{

		//SHA3.Net library provides SHA3 hasing algotithem but wihtout key so you can generate Hash with key using this package
		internal static byte[] Compute_SHA3_256(byte[] toBeHashed)
		{
			using (var sha3 = Sha3.Sha3256())
			{
				return sha3.ComputeHash(toBeHashed);
			}
		}

		internal static byte[] Compute_SHA3_224(byte[] toBeHashed)
		{
			using (var sha3 = Sha3.Sha3224())
			{
				return sha3.ComputeHash(toBeHashed);
			}
		}

		internal static byte[] Compute_SHA3_512(byte[] toBeHashed)
		{
			using (var sha3 = Sha3.Sha3512())
			{
				return sha3.ComputeHash(toBeHashed);
			}
		}
		internal static byte[] Compute_SHA3_384(byte[] toBeHashed)
		{
			using (var sha3 = Sha3.Sha3384())
			{
				return sha3.ComputeHash(toBeHashed);
			}
		}
	}
}
