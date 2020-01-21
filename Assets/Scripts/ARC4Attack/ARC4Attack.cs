// http://inaz2.hatenablog.com/entry/2013/11/30/233649

using System.Collections.Generic;
using System.Security.Cryptography;

public static class ARC4Attack
{
    public static Dictionary<byte, int> Attack(byte[] message)
    {
        var dict = new Dictionary<byte, int>(256);
        var key = new byte[128];

        using (var rng = new RNGCryptoServiceProvider())
        {
            for (var i = 0; i < 65536; i++)
            {
                rng.GetBytes(key);
                var enc = Crypto.ARC4.Encode(message, key);
                var k = enc[1];
                if (dict.ContainsKey(k))
                {
                    dict[k] += 1;
                }
                else
                {
                    dict[k] = 1;
                }
            }

        }

        return dict;
    }
}
