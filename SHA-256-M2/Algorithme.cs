using System.Text;

namespace SHA_256_M2
{
    /// <summary>
    /// Cette classe implémente l'algorithme SHA-256.
    /// </summary>
    public static class Algorithme
    {
        #region Prétraitement

        /// <summary>
        /// Effectue le prétraitement du message : conversion en binaire, ajout de padding, ajout de la longueur,
        /// puis découpe en blocs de 512 bits.
        /// </summary>
        private static List<string> Pretraitement(string message)
        {
            var motEnBinaire = EncoderEnBinaire(message);

            motEnBinaire += "1"; // Ajout du bit '1'
            motEnBinaire = Rembourrer(motEnBinaire); // Ajout de zéros jusqu'à atteindre 448 bits
            motEnBinaire =
                AjouterLongueurMessage(motEnBinaire,
                    message.Length); // Ajout de la longueur du message en binaire sur 64 bits

            return DecouperEnBlocs(motEnBinaire); // Découpe en blocs de 512 bits.
        }

        /// <summary>
        /// Convertit un message texte en une chaîne de caractères binaire.
        /// </summary>
        private static string EncoderEnBinaire(string message)
        {
            var binaire = new StringBuilder();

            foreach (var caractere in message)
            {
                // Convertit chaque caractère en binaire sur 8 bits (ASCII).
                binaire.Append(Convert.ToString(caractere, 2).PadLeft(8, '0'));
            }

            return binaire.ToString();
        }

        /// <summary>
        /// Ajoute des zéros (padding) jusqu'à ce que la longueur du message soit de 448 bits (modulo 512).
        /// </summary>
        private static string Rembourrer(string binaire)
        {
            while (binaire.Length % 512 != 448)
            {
                binaire += "0";
            }

            return binaire;
        }

        /// <summary>
        /// Ajoute la longueur du message original (en bits) en tant que valeur binaire de 64 bits à la fin.
        /// </summary>
        private static string AjouterLongueurMessage(string binaire, int longueurMessage)
        {
            var longueurBinaire = Convert.ToString(longueurMessage * 8, 2).PadLeft(64, '0'); // Longueur en bits.
            return binaire + longueurBinaire;
        }

        /// <summary>
        /// Découpe une chaîne binaire en blocs de 512 bits.
        /// </summary>
        private static List<string> DecouperEnBlocs(string binaire)
        {
            var blocs = new List<string>();
            for (var i = 0; i < binaire.Length; i += 512)
            {
                blocs.Add(binaire.Substring(i, Math.Min(512, binaire.Length - i)));
            }

            return blocs;
        }

        #endregion

        #region Traitement des blocs

        /// <summary>
        /// Génère 64 mots de 32 bits à partir d'un bloc de 512 bits.
        /// </summary>
        private static List<uint> GenererMots(string bloc)
        {
            var mots = new List<uint>();

            // 16 premiers mots (1 mot = 32 bits)
            for (var i = 0; i < 16; i++)
            {
                var motBinaire = bloc.Substring(i * 32, 32);
                mots.Add(Convert.ToUInt32(motBinaire, 2));
            }

            // 48 mots suivants (générés à partir des 16 premiers avec les fonctions sigma0 et sigma1)
            for (var i = 16; i < 64; i++)
            {
                var s0 = Sigma0Mots(mots[i - 15]);
                var s1 = Sigma1Mots(mots[i - 2]);
                var nouveauMot = mots[i - 16] + s0 + mots[i - 7] + s1;

                mots.Add(nouveauMot);
            }

            return mots;
        }

        /// <summary>
        /// Fonction logique sigma0 utilisée dans la génération des mots Wt
        /// </summary>
        private static uint Sigma0Mots(uint x)
        {
            return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3);
        }

        /// <summary>
        /// Fonction logique sigma1 utilisée dans la génération des mots Wt
        /// </summary>
        private static uint Sigma1Mots(uint x)
        {
            return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10);
        }

        #endregion

        #region Iterations

        /// <summary>
        /// Effectue 64 itérations pour mettre à jour les valeurs de hachage.
        /// </summary>
        private static uint[] BouclePrincipale(List<uint> mots)
        {
            var s = new uint[8];

            // S[i] = Hi
            Array.Copy(Constantes.H, s, 8);

            for (var t = 0; t < 64; t++)
            {
                var t1 = s[7] + Sigma1(s[4]) + Ch(s[4], s[5], s[6]) + Constantes.K[t] + mots[t];
                var t2 = Sigma0(s[0]) + Maj(s[0], s[1], s[2]);

                // MAJ des variables de hachage
                s[7] = s[6];
                s[6] = s[5];
                s[5] = s[4];
                s[4] = s[3] + t1;
                s[3] = s[2];
                s[2] = s[1];
                s[1] = s[0];
                s[0] = t1 + t2;
            }

            // Ajout des valeurs initiales (H) aux valeurs finales
            for (var i = 0; i < 8; i++)
            {
                s[i] += Constantes.H[i];
            }

            return s;
        }

        /// <summary>
        /// Effectue une rotation circulaire vers la droite.
        /// </summary>
        private static uint RotR(uint valeur, int bits)
        {
            return (valeur >> bits) | (valeur << (32 - bits));
        }

        /// <summary>
        /// Fonction logique sigma1 utilisée dans le calcul de T1.
        /// </summary>
        private static uint Sigma1(uint x)
        {
            return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);
        }

        /// <summary>
        /// Fonction logique sigma0 utilisée dans le calcul de T2.
        /// </summary>
        private static uint Sigma0(uint x)
        {
            return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);
        }

        /// <summary>
        /// Fonction logique Ch utilisée dans le calcul de T1.
        /// </summary>
        private static uint Ch(uint x, uint y, uint z)
        {
            return (x & y) ^ (~x & z);
        }

        /// <summary>
        /// Fonction logique Maj utilisée dans le calcul de T2.
        /// </summary>
        private static uint Maj(uint x, uint y, uint z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        #endregion

        /// <summary>
        /// Applique l'algorithme complet sur une chaine et renvoie le hashage obtenu.
        /// </summary>
        public static string Hasher(string message)
        {
            var blocs = Pretraitement(message);

            uint[] hashFinal = null;

            foreach (var bloc in blocs)
            {
                var mots = GenererMots(bloc);
                hashFinal = BouclePrincipale(mots);
            }

            // Conversion uint[] -> chaîne
            var hashHex = new StringBuilder();
            foreach (var valeur in hashFinal)
            {
                hashHex.Append(valeur.ToString("x8"));
            }

            return hashHex.ToString();
        }
    }
}