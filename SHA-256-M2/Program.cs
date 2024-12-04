using System.Security.Cryptography;
using System.Text;

namespace SHA_256_M2
{
    class Program
    {
        static void Main(string[] args)
        {
            var message = "abc";

            // Hash généré par l'algorithme implémenté
            var messageHashe = Algorithme.Hasher(message);

            // Hash généré par l'implémentation officielle de .NET
            var hashOfficiel = Sha256(message);

            Console.WriteLine($"Résultat - Algorithme implémenté : {messageHashe}");
            Console.WriteLine($"Résultat - Algorithme officiel   : {hashOfficiel}");
        }

        /// <summary>
        /// Calcule le hash SHA-256 d'une chaîne de caractères en utilisant l'implémentation officielle de .NET.
        ///
        /// Méthode utilisée uniquement pour comparer les résultats.
        ///
        /// Source : https://stackoverflow.com/questions/12416249/hashing-a-string-with-sha256
        /// </summary>
        static string Sha256(string randomString)
        {
            var crypt = new System.Security.Cryptography.SHA256Managed();
            var hash = new System.Text.StringBuilder();
            byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(randomString));
            foreach (byte theByte in crypto)
            {
                hash.Append(theByte.ToString("x2"));
            }

            return hash.ToString();
        }
    }
}