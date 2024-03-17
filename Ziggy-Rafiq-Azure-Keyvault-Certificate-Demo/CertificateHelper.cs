using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Ziggy_Rafiq_Azure_Keyvault_Certificate_Demo
{
    public static class CertificateHelper
    {
       public static X509Certificate2 LoadCertificateFromKeyVault(string keyVaultUri, string secretName)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var keyVaultClient = new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));

            var secret = keyVaultClient.GetSecretAsync($"{keyVaultUri}/secrets/{secretName}").Result;
            var certBytes = Convert.FromBase64String(secret.Value);

            return new X509Certificate2(certBytes);
        }

    }
}
