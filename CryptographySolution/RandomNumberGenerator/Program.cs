using RandomNumberGenerator ;

internal class Program
{
	private static void Main(string[] args)
	{
		Console.WriteLine("Random Number Generator in .Net");
		Console.WriteLine("-------------------------------");
		Console.WriteLine();

		// this will generate 10 random number 
		for (int i = 0; i < 10; i++)
		{
			// this will generate a 32 bit random number and print it to screen
			Console.WriteLine("Random Number " + i + " : " + Convert.ToBase64String(RandomNumGen.GenerateRandomNumber(32)));
		}
		Console.ReadLine();
	}
}