using System.Text;

namespace CdelEduDecrypt;

public static class Helpers
{
    public static int Load(this byte[] buffer, int offset) => BitConverter.ToInt32(buffer, offset);

    public static int Rotl(this int value, int count) => (value << count) | (value >>> (32 - count));
    
    public static string Decode(this byte[] input) => Encoding.UTF8.GetString(input);

    public static string ToHex(this byte[] input) => Convert.ToHexStringLower(input);
}