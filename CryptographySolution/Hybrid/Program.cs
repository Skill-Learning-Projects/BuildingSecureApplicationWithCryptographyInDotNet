using Hybrid.EncryptionDecryption;
using Hybrid.HybridEncryptionDecryptionWithIntegrity;
using Hybrid.WithIntegrityAndSignature;
using Hybrid.WithIntegrityAndSignatureGCM;

namespace Hybrid
{
	internal class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("DEMONSTRATING HYBRID ENCRYPTION AND DECRYPTION");
			Console.WriteLine("****************************************************");

			var hybrid = new HybridEncryptionDecryption();
			hybrid.DemonstarteHybridEncryptionDecryption();

			var hybridwithIntegrity = new HybridWithIntegrity();
			hybridwithIntegrity.DemonstarteHybridWithIntegrity();

			var hybridwithIntegrityAndSign = new HybridWithIntegrityAndSignature();
			hybridwithIntegrityAndSign.DemonstrateHybridWithIntegrityAndSignature();

			var hybridwithIntegrityAndSignGCM = new HybridWithIntegrityAndSignatureGCM();
			hybridwithIntegrityAndSignGCM.DemonstrateHybridWithIntegrityAndSignatureGCM();

			Console.ReadLine();
		}
	}
}
