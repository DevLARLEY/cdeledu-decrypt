namespace CdelEduDecrypt;

class Program : Constants
{
    private static byte[] Decrypt64BitBlock(byte[] input)
    {
        /*
         * CdelEdu Reverse engineered key decryption
         * Author: github.com/DevLARLEY
         */
        var c0 = input[..4];
        var c1 = input[4..8];

        var h2 = BitConverter.ToInt32(c0);
        var h3 = BitConverter.ToInt32(c1);

        var g = h2;
        var j = h3;

        int i, o, q;

        i = (g ^ j >>> 4) & 0x0F0F0F0F;
        j = i << 4 ^ j;
        g = g ^ i;
        i = (j & 0x0000FFFF) ^ g >>> 16;

        j = i ^ j;
        g = i << 16 ^ g;
        i = (j >>> 2 ^ g) & 0x33333333;

        g = i ^ g;
        j = i << 2 ^ j;
        i = (g >>> 8 ^ j) & 0x00FF00FF;

        o = i ^ j;
        g = i << 8 ^ g;
        q = (o >>> 1 ^ g) & 0x55555555;

        i = (q ^ g).Rotl(3);
        g = (i ^ K.Load(38 * 4)).Rotl(28);

        j = K.Load(37 * 4) ^ i;
        j = M.Load(j & 252) ^
            M.Load((j >>> 8 & 252) + 512) ^
            M.Load((j >>> 16 & 252) + 1024) ^
            M.Load((j >>> 24 & 252) + 1536) ^
            M.Load((g & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^
            (q << 1 ^ o).Rotl(3);

        g = j ^ K.Load(35 * 4);

        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(36 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;

        g = i ^ K.Load(33 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(34 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;

        g = j ^ K.Load(31 * 4);
        
        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(32 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;
        
        g = i ^ K.Load(29 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(30 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ K.Load(27 * 4);
        
        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(28 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;
        
        g = i ^ K.Load(25 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(26 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ K.Load(23 * 4);
        
        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(24 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;
        
        g = i ^ K.Load(21 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(22 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ K.Load(19 * 4);
        
        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(20 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;
        
        g = i ^ K.Load(17 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(18 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ K.Load(15 * 4);
        
        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(16 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;
        
        g = i ^ K.Load(13 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(14 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ K.Load(11 * 4);
        
        i = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ K.Load(12 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ i;
        
        g = i ^ K.Load(9 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (i ^ K.Load(10 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ K.Load(7 * 4);

        o = j.Rotl(29);

        g = (M.Load(((j = (j ^ K.Load(8 * 4)).Rotl(28)) >>> 24 & 252) + 1792) ^
             M.Load((j >>> 16 & 252) + 1280) ^
             M.Load((j >>> 8 & 252) + 768) ^
             M.Load((j & 252) + 256) ^
             M.Load((g >>> 24 & 252) + 1536) ^
             M.Load((g >>> 16 & 252) + 1024) ^
             M.Load((g >>> 8 & 252) + 512) ^
             M.Load(g & 252) ^ i).Rotl(29);
        
        j = (o ^ g >>> 1) & 0x55555555;
        i = j ^ o;
        g = j << 1 ^ g;

        j = (i >>> 8 ^ g) & 0x00FF00FF;
        g = j ^ g;
        j = j << 8 ^ i;
        
        i = (g >>> 2 ^ j) & 0x33333333;
        g = i << 2 ^ g;
        j = i ^ j;
        
        i = (g & 65535) ^ j >>> 16;
        g = i ^ g;
        j = i << 16 ^ j;
        
        i = (g >>> 4 ^ j) & 0x0F0F0F0F;
        h2 = i ^ j;
        h3 = i << 4 ^ g;

        return [..BitConverter.GetBytes(h2), ..BitConverter.GetBytes(h3)];
    }

    private static (byte[] Key, byte[] Iv) Decrypt(byte[] ciphertext)
    {
        if (ciphertext.Length % 8 != 0)
            throw new ArgumentException("Ciphertext must be a multiple of 8 bytes long");
        
        var plaintext = new byte[ciphertext.Length - 8];
        
        for (var i = 8; i < ciphertext.Length; i += 8)
        {
            var result = Decrypt64BitBlock(ciphertext[i..(i+8)]);

            if (result.Length != 8)
                throw new InvalidOperationException("Transformed block must be exactly 8 bytes.");

            Buffer.BlockCopy(result, 0, plaintext, i-8, 8);
        }

        for (var i = 0; i < plaintext.Length; i++)
        {
            if (plaintext[i] == 0x02)
            {
                plaintext[i] = 0x3d; // '='
            }
        }

        var keyString = plaintext.Decode();

        return (Convert.FromBase64String(keyString[..24]), Convert.FromBase64String(keyString[24..]));
    }

    private static string ModifyRawKey(string rawKey)
    {
        var key = rawKey[16..^8];
        return key.Replace("-", "/").Replace(".", "+").Replace("_", "=");
    }
    
    static void Main(string[] args)
    {
        Console.WriteLine("CdelEdu Key Decrypter by github.com/DevLARLEY");
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: CdelEduDecrypt.exe [key]");
            Environment.Exit(0);
        }
        
        var modifiedKey = ModifyRawKey(args[0]);
        var encryptedKey = Convert.FromBase64String(modifiedKey);
        var decrypted = Decrypt(encryptedKey);
        
        Console.WriteLine($"Key: {decrypted.Key.ToHex()} IV: {decrypted.Iv.ToHex()}");
    }
}