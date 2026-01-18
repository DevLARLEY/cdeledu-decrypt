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

        int l, p, q;

        l = (g ^ j >>> 4) & 0x0F0F0F0F;
        j = l << 4 ^ j;
        g = g ^ l;
        l = (j & 0x0000FFFF) ^ g >>> 16;

        j = l ^ j;
        g = l << 16 ^ g;
        l = (j >>> 2 ^ g) & 0x33333333;

        g = l ^ g;
        j = l << 2 ^ j;
        l = (g >>> 8 ^ j) & 0x00FF00FF;

        p = l ^ j;
        g = l << 8 ^ g;
        q = (p >>> 1 ^ g) & 0x55555555;

        l = (q ^ g).Rotl(3);
        g = (l ^ I.Load(54 * 4)).Rotl(28);

        j = I.Load(53 * 4) ^ l;
        j = M.Load(j & 252) ^
            M.Load((j >>> 8 & 252) + 512) ^
            M.Load((j >>> 16 & 252) + 1024) ^
            M.Load((j >>> 24 & 252) + 1536) ^
            M.Load((g & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^
            (q << 1 ^ p).Rotl(3);

        g = j ^ I.Load(51 * 4);

        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(52 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;

        g = l ^ I.Load(49 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(50 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;

        g = j ^ I.Load(47 * 4);
        
        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(48 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;
        
        g = l ^ I.Load(45 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(46 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ I.Load(43 * 4);
        
        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(44 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;
        
        g = l ^ I.Load(41 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(42 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ I.Load(39 * 4);
        
        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(40 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;
        
        g = l ^ I.Load(37 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(38 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ I.Load(35 * 4);
        
        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(36 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;
        
        g = l ^ I.Load(33 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(34 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ I.Load(31 * 4);
        
        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(32 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;
        
        g = l ^ I.Load(29 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(30 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ I.Load(27 * 4);
        
        l = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (j ^ I.Load(28 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ l;
        
        g = l ^ I.Load(25 * 4);
        
        j = M.Load(g & 252) ^
            M.Load((g >>> 8 & 252) + 512) ^
            M.Load((g >>> 16 & 252) + 1024) ^
            M.Load((g >>> 24 & 252) + 1536) ^ 
            M.Load(((g = (l ^ I.Load(26 * 4)).Rotl(28)) & 252) + 256) ^
            M.Load((g >>> 8 & 252) + 768) ^
            M.Load((g >>> 16 & 252) + 1280) ^
            M.Load((g >>> 24 & 252) + 1792) ^ j;
        
        g = j ^ I.Load(23 * 4);

        p = j.Rotl(29);

        g = (M.Load(((j = (j ^ I.Load(24 * 4)).Rotl(28)) >>> 24 & 252) + 1792) ^
             M.Load((j >>> 16 & 252) + 1280) ^
             M.Load((j >>> 8 & 252) + 768) ^
             M.Load((j & 252) + 256) ^
             M.Load((g >>> 24 & 252) + 1536) ^
             M.Load((g >>> 16 & 252) + 1024) ^
             M.Load((g >>> 8 & 252) + 512) ^
             M.Load(g & 252) ^ l).Rotl(29);
        
        j = (p ^ g >>> 1) & 0x55555555;
        l = j ^ p;
        g = j << 1 ^ g;

        j = (l >>> 8 ^ g) & 0x00FF00FF;
        g = j ^ g;
        j = j << 8 ^ l;
        
        l = (g >>> 2 ^ j) & 0x33333333;
        g = l << 2 ^ g;
        j = l ^ j;
        
        l = (g & 65535) ^ j >>> 16;
        g = l ^ g;
        j = l << 16 ^ j;
        
        l = (g >>> 4 ^ j) & 0x0F0F0F0F;
        h2 = l ^ j;
        h3 = l << 4 ^ g;

        return [..BitConverter.GetBytes(h2), ..BitConverter.GetBytes(h3)];
    }

    private static byte[] Decrypt(byte[] ciphertext)
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

        return Convert.FromBase64String(keyString[..24]);
    }

    private static string ModifyRawKey(string rawKey)
    {
        var key = rawKey[8..^16];
        return key.Replace("-", "/").Replace(".", "+").Replace("_", "=");
    }
    
    static void Main(string[] args)
    {
        Console.WriteLine("CdelEdu Key Decrypter by github.com/DevLARLEY (JS v3.6/drm4pc v4)");
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: CdelEduDecrypt.exe [key]");
            Environment.Exit(0);
        }
        
        var modifiedKey = ModifyRawKey(args[0]);
        var encryptedKey = Convert.FromBase64String(modifiedKey);
        var decrypted = Decrypt(encryptedKey);
        
        Console.WriteLine($"Key: {decrypted.ToHex()}");
    }
}