using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Hashing
{
	internal static class Hashing
	{

		internal static byte[] ComputeHashSha1(byte[] toBeHashed)
		{
			using (var sha1 = SHA1.Create())
			{
				return sha1.ComputeHash(toBeHashed);
			}
		}

		internal static byte[] ComputeHashSha256(byte[] toBeHashed)
		{
			using (var sha256 = SHA256.Create())
			{
				return sha256.ComputeHash(toBeHashed);
			}
		}

		internal static byte[] ComputeHashSha512(byte[] toBeHashed)
		{
			using (var sha512 = SHA512.Create())
			{
				return sha512.ComputeHash(toBeHashed);
			}
		}

		internal static byte[] ComputeHashMD5(byte[] toBeHashed)
		{
			using (var md5 = MD5.Create())
			{
				return md5.ComputeHash(toBeHashed);
			}
		}
	}
}
