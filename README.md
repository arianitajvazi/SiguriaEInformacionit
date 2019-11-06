
Sigurimi i Informacionit: Detyra 1
=

Ky program është aplikacion konzolë, bënë  gjetjen e çelësit me të cilin është enkriptuar teksti **dbde740b07d8af1222669b7388bc5d3a** si dhe dekriptimin e këtij teksti, duke marrë parasysh kushtet në bazë të të cilave mund të përcaktohet çelësi adekuat.



Udhëzime rreth ekzekutimit të programit
-


Programi i zhvilluar, e kryen punën e tij në disa hapa kryesorë, në renditjen si në vijim:

- Bënë leximin e txt file në të cilin gjenden 100 000 rekorde të çelësave deterministik 14 bajtësh
- Bënë filtrimin e çelësave në bazë të kushteve **k7<31,  k3>k4,  k5<1E**, ku 'k' paraqet bajtin në pozitën përkatëse, ndërsa *31* dhe *1E* janë numra HEX.
- Gjeneron një listë të shifrave HEX në rangun *0000* - *FFFF*, në mënyrë që të kompletojë çelësat e mundshëm
- Bënë dekriptimin e tekstit të enkriptuar **dbde740b07d8af1222669b7388bc5d3a** 
- Shfaqë në *console* rezultatin e dekriptuar


Mënyra e gjetjes së çelësit dhe dekriptimi i mesazhit
-

Gjetja e çelësit është bërë duke u mbështetur në mangësitë e sistemit:

- Shfrytëzimi i 100 000 rekordeve të çelësave deterministik
- Zvogëlimi i çelësave të mundshëm deterministik përmes filtrimit me kushtet përmendura më sipër 
- Përdorimi i *Brute force attack*, gjetja e çelësit duke krijuar çelësa 16bajtësh,

 
**Hapi i parë, leximi i fajllit *keys.txt*  dhe ruajtja e çelësave deterministik të lexuar përmes:**

```c#
System.IO.File.ReadAllLines(@"D:\keys.txt");
```
 

**Hapi i dytë, filtrimi i çelësave deterministik (çelësave të lexuar në fajll) përmes kushteve:**
```c#
if (index7Dec < 49 && index3Dec > index7Dec && index5Dec < 30)
{                   
	matchingKeys.Add(currentRow);
    Console.writeLine(currentRow);
}
```
- Vlera decimale e bajtit në pozitën 7 të jetë më e vogël se 79
- Vlera decimale e bajtit në pozitën 3 të jetë më e madhe se vlera decimale e bajtit në pozitën 7
- Vlera decimale e bajtit në pozitën 5 të jetë më e vogël se 30

Në këtë rast janë fituar 3 çelësa të mundshëm deterministik të cilët mund të jenë pjesë e çelësit të kërkuar.

**Hapi i tretë, gjenerimi i pjesës së mbetur të HEX vlerave të çelësave:**
```c#
 private static List<String> RandomHexString()
        {
            List<String> generatedRandomHex = new List<string>();
            for (int i = 0x00; i <= 0xFFFF; i++)
            {
	            // konvertimi i vlerës në tipin string
                string str = i.ToString("X");
				...
                generatedRandomHex.Add(str);
            }
            return generatedRandomHex;
        }
```

Meqenëse gjatësia e çelësit te AES 128 ECB është 128 bit (16Byte), çelësat deterministik janë të mangët për të dekriptuar *ciphertext*-in. Prandaj gjenerohen vlera të mundshme HEX për t'i përmbushur çelësat.

**Hapi i katërt, dekriptimi i ciphertext-it**

Meqenëse nuk e dimë saktësisht çelësin për dekriptim, është përdorur sulmi *Brute force attack*, duke përdorur si çelës për dekriptim kombinimin e çelësave deterministik me vlerat e mundshme HEX të gjeneruara në hapin e tretë. 
```c#
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
```

**Hapi i fundit, përcaktimi i çelësit të kërkuar duke u bazuar në "përvojën" se sistemi i dërgon mesazhet në formatin 'GR XX KODI XXXXX'**
Në rastin tonë, kombinimi i tekstit është i formës: "GR 06 KODI XXXX". Secili tekst i dekriptuar, është dekoduar në formatin UFT-8 dhe më pas është bërë filtrimi i tyre sipas:
```c#
decrypted = Encoding.UTF8.GetString(Decrypt(cipherText, fullKey));
if (decrypted.Contains("GR 06"))
{
	printSolution(fullKey, decrypted);
	foundKey = true;
	break;
}
```

Në këtë rast është fituar teksti: 
**GR 06 KODI 29813**
ndërsa çelësi i përdodur pë dekriptim është:
**65bc039666009d2b83c349b59f16735C**


Analiza teorike
--------
Tre çelësat deterministik të fituar me filtrimin e përmbajtjes së fajllit *keys.txt* janë të pamjaftueshëm për dekriptim, pasi që gjatësia e tyre është 14 byte dhe për tu përdorur si çelës i mundshëm për dekriptim me AES 128 ECB, atyre duhet t'u shtohen edhe 2 byte (4 shifra HEX) pasi që gjatësia e çelësit te algoritmi i përdorur është 16 byte. 
Kombinimet të cilat duhet të shtohen janë prej 0000 deri në FFFF, duke krijuar kështu një numër total të 65536 kombinimeve. Meqenëse kemi 3 çelësa kandidat të cilët do të përdoren për dekriptim, atëherë numri i kombinimeve të çelësave bëhet:
```
	3 * 65536 = 196608
```
Secili prej këtyre çelësave të fituar, tenton të dekriptojë ciphertext-in e dhënë, duke krijuar në total 196608 kombinime të teksteve të dekriptuara, ku vetëm njëri prej tyre plotëson kushtin që përmban tekstin 'GR 06 KODI XXXXX'.

Në rastin më të mirë, ky çelës gjendet në tentimin e parë, nëse çelësit të parë i shtohet vlera 0000, ndërsa në rastin më të keq, në tentimin 196608 nëse çelësit të fundit i shtohet vlera FFFF, mirëpo për pajisjet e sotme kompjuterike, ky proces i dekriptimit është shumë i shpejtë.
