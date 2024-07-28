using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.ComponentModel.DataAnnotations;

namespace RandomNumberGenerator
{
	public static class RandomNumGen
	{
		// this funciton generates true random number using cryptography based on length provided
		public static byte[] GenerateRandomNumber(int lenth)
		{
			using (var randomNumbeGenerator =  new RNGCryptoServiceProvider())
			{
				var randomNumber = new byte[lenth];
				randomNumbeGenerator.GetBytes(randomNumber);
				return randomNumber;
			}
		}

	}
}
