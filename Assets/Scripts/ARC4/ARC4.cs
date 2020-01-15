// https://gist.github.com/hoiogi/89cf2e9aa99ffc3640a4
// http://inaz2.hatenablog.com/entry/2013/11/30/233649

namespace Crypto
{
    public static class ARC4
    {
        private static byte[] s_S = new byte[256];

        static ARC4()
        {
            for (var i = 0; i < 256; i++)
            {
                s_S[i] = (byte)i;
            }
        }

        private static byte[] KSA(byte[] key)
        {
            var j = 0;
            var s = new byte[s_S.Length];
            System.Array.Copy(s_S, s, s.Length);
            for (var i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }

            return s;
        }

        public static byte[] Encode(byte[] data, byte[] key)
        {
            var s = KSA(key);
            var result = new byte[data.Length];

            var (i, j) = (0, 0);

            for (var index = 0; index < data.Length; index++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
                var k = s[(s[i] + s[j]) % 256];

                result[index] = (byte)(data[index] ^ k);
            }

            return result;
        }
    }

}
