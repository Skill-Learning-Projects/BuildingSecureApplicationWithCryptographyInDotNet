namespace DigitalSignatures
{
	internal class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("DEMONSTRATING DIGITAL SIGNATURES");
			Console.WriteLine("****************************************************");

			var digitalsig = new DigitalSignature();
			digitalsig.SignAndVerifyData();

			var newdigitalsig = new NewDigitalSignature();
			newdigitalsig.SignAndVerifyData();
			newdigitalsig.SignAndVerifyDataWithKey();

			Console.ReadLine();

		}
	}
}
