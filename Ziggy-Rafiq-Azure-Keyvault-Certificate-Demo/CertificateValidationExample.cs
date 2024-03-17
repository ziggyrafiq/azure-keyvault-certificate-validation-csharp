using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;


namespace Ziggy_Rafiq_Azure_Keyvault_Certificate_Demo
{
    public static class CertificateValidationExample
    {
       public static void ValidateCertificate(X509Certificate2 cert, X509Certificate2 root)
        {
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            var isValid = chain.Build(cert);

            if (isValid)
            {
                var chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                isValid = chainRoot.RawData.SequenceEqual(root.RawData);

                if (isValid)
                {
                    Console.WriteLine("Certificate chain is valid, and the root certificate matches the specified root.");
                    Console.WriteLine($"Subject: {cert.Subject}, Issuer: {cert.Issuer}, Valid From: {cert.NotBefore}, Valid Until: {cert.NotAfter}");
                }
                else
                {
                    Console.WriteLine("Certificate chain is valid, but the root certificate does not match the specified root.");
                }
            }
            else
            {
                Console.WriteLine($"Certificate chain validation failed. ChainStatus: {GetChainStatus(chain.ChainStatus)}");
            }
        }

        static string GetChainStatus(X509ChainStatus[] chainStatus)
        {
            return string.Join(Environment.NewLine, chainStatus.Select(status => $"Status: {status.Status}, Status Information: {status.StatusInformation}"));
        }

    }
}
