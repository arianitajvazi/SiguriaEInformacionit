using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SiguriaeInformacionit
{
    class Program
    {
        static void Main(string[] args)
        {
            string cipherText = "dbde740b07d8af1222669b7388bc5d3a";

            List<String> missingKeyHex = RandomHexString();
            List<String> matchingKeys = new List<string>();

            string[] lines = System.IO.File.ReadAllLines(@"D:\keys.txt");

            int count = 0;

            Console.WriteLine("------Celesat deterministik qe i permbushin kushtet------");
            foreach (var currentRow in lines)
            {

                string index7 = currentRow[14].ToString() + currentRow[15].ToString();
                int index7Dec = int.Parse(index7, System.Globalization.NumberStyles.HexNumber);

                string index3 = currentRow[6].ToString() + currentRow[7].ToString();
                int index3Dec = int.Parse(index3, System.Globalization.NumberStyles.HexNumber);

                string index5 = currentRow[10].ToString() + currentRow[11].ToString();
                int index5Dec = int.Parse(index5, System.Globalization.NumberStyles.HexNumber);

                if (index7Dec < 49 && index3Dec > index7Dec && index5Dec < 30)
                {
                    count++;                   
                    matchingKeys.Add(currentRow);
                    Console.WriteLine(currentRow);
                }
            }
            Console.WriteLine("--------------------------------------------------------");
            Console.WriteLine();

            bool foundKey = false;
            foreach (var randomHex in missingKeyHex)
            {
                    string decrypted = "";

                    foreach (var currentKey in matchingKeys)
                    {
                        string fullKey = currentKey + randomHex;
                        decrypted = Encoding.UTF8.GetString(Decrypt(cipherText, fullKey));
                        if (decrypted.Contains("GR 06"))
                        {
                            printSolution(fullKey, decrypted);
                            foundKey = true;
                            break;
                        }

                        if (foundKey)
                        {
                            break;
                        }
                }
            }
            Console.ReadLine();
        }

        public static void printSolution(string key, string message)
        {
            Console.WriteLine("----------------- Teksti i dekriptuar ------------------");
            Console.WriteLine("|                                                      |");
            Console.WriteLine("|                      " + message + "                |");
            Console.WriteLine("|                                                      |");
            Console.WriteLine("--------------------------------------------------------");

            Console.WriteLine("----------- Celesi i perdorur per enkriptim ------------");
            Console.WriteLine("|                                                      |");
            Console.WriteLine("|           " + key + "           |");
            Console.WriteLine("|                                                      |");
            Console.WriteLine("--------------------------------------------------------");
        }

        private static List<String> RandomHexString()
        {
            List<String> generatedRandomHex = new List<string>();
            for (int i = 0x00; i <= 0xFFFF; i++)
            {
                string str = i.ToString("X");

                if (str.Length == 1)
                {
                    str = "000" + str;
                }
                else if (str.Length == 2)
                {
                    str = "00" + str;
                }
                else if (str.Length == 3)
                {
                    str = "0" + str;
                }
                generatedRandomHex.Add(str);
            }
            return generatedRandomHex;
        }
       
        public static byte[] HexadecimalStringToByteArray(string input)
        {
            var outputLength = input.Length / 2;
            var output = new byte[outputLength];
            using (var sr = new StringReader(input))
            {
                for (var i = 0; i < outputLength; i++)
                    output[i] = Convert.ToByte(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), 16);
            }
            return output;
        }

        static byte[] Decrypt(string cipherText, string Key)
        {
            byte[] plaintext = null;
            byte[] cipher = HexadecimalStringToByteArray(cipherText) ;
            byte[] key = HexadecimalStringToByteArray(Key);

            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.Zeros;
                aes.Mode = CipherMode.ECB;
                aes.Key = key;
                ICryptoTransform decryptor = aes.CreateDecryptor();
                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (BinaryReader reader = new BinaryReader(cs, Encoding.UTF8))
                            try
                            {
                                plaintext = reader.ReadBytes(cipher.Length);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                            }
                    }
                }
            }
            return plaintext;
        }
    }
}
