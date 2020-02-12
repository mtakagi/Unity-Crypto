// https://github.com/golang/crypto/blob/master/salsa20/salsa20.go

namespace Crypto
{
    public static class Salsa20
    {
        private static uint ROTL(uint a, uint b) => ((a << (int)(b)) | (a >> (32 - (int)(b))));
        private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            b ^= ROTL(a + d, 7);
            c ^= ROTL(b + a, 9);
            d ^= ROTL(c + b, 13);
            a ^= ROTL(d + c, 18);
        }
        private const int ROUNDS = 20;

        private static void SalsaBlock(uint[] output, uint[] input)
        {
            int i;
            var x = new uint[16];

            for (i = 0; i < 16; ++i)
            {
                x[i] = input[i];
            }
            // 10 loops × 2 rounds/loop = 20 rounds
            for (i = 0; i < ROUNDS; i += 2)
            {
                // Odd round
                QR(ref x[0], ref x[4], ref x[8], ref x[12]); // column 0
                QR(ref x[5], ref x[9], ref x[13], ref x[1]); // column 1
                QR(ref x[10], ref x[14], ref x[2], ref x[6]); // column 2
                QR(ref x[15], ref x[3], ref x[7], ref x[11]); // column 3
                // Even round
                QR(ref x[0], ref x[1], ref x[2], ref x[3]); // diagonal 1 (main diagonal)
                QR(ref x[5], ref x[6], ref x[7], ref x[4]); // diagonal 2
                QR(ref x[10], ref x[11], ref x[8], ref x[9]); // diagonal 3
                QR(ref x[15], ref x[12], ref x[13], ref x[14]); // diagonal 4
            }
            for (i = 0; i < 16; ++i)
            {
                output[i] = x[i] + input[i];
            }
        }

        private static byte[] NormalEncode(byte[] input, byte[] key, byte[] nonce)
        {
            var state = new uint[16];

            state[0] = (uint)'e' | (uint)'x' << 8 | (uint)'p' << 16 | (uint)'a' << 24; // expa
            state[5] = (uint)'n' | (uint)'d' << 8 | (uint)' ' << 16 | (uint)'3' << 24; // nd 3
            state[10] = (uint)'2' | (uint)'-' << 8 | (uint)'b' << 16 | (uint)'y' << 24; // 2-by
            state[15] = (uint)'t' | (uint)'e' << 8 | (uint)' ' << 16 | (uint)'k' << 24; // te k

            state[1] = (uint)key[0] | (uint)key[1] << 8 | (uint)key[2] << 16 | (uint)key[3] << 24;
            state[2] = (uint)key[4] | (uint)key[5] << 8 | (uint)key[6] << 16 | (uint)key[7] << 24;
            state[3] = (uint)key[8] | (uint)key[9] << 8 | (uint)key[10] << 16 | (uint)key[11] << 24;
            state[4] = (uint)key[12] | (uint)key[13] << 8 | (uint)key[14] << 16 | (uint)key[15] << 24;
            state[11] = (uint)key[16] | (uint)key[17] << 8 | (uint)key[18] << 16 | (uint)key[19] << 24;
            state[12] = (uint)key[20] | (uint)key[21] << 8 | (uint)key[22] << 16 | (uint)key[23] << 24;
            state[13] = (uint)key[24] | (uint)key[25] << 8 | (uint)key[26] << 16 | (uint)key[27] << 24;
            state[14] = (uint)key[28] | (uint)key[29] << 8 | (uint)key[30] << 16 | (uint)key[31] << 24;

            state[6] = (uint)nonce[0] | (uint)nonce[1] << 8 | (uint)nonce[2] << 16 | (uint)nonce[3] << 24;
            state[7] = (uint)nonce[4] | (uint)nonce[5] << 8 | (uint)nonce[6] << 16 | (uint)nonce[7] << 24;
            state[8] = (uint)nonce[8] | (uint)nonce[9] << 8 | (uint)nonce[10] << 16 | (uint)nonce[11] << 24;
            state[9] = (uint)nonce[12] | (uint)nonce[13] << 8 | (uint)nonce[14] << 16 | (uint)nonce[15] << 24;

            using (var inputStream = new System.IO.MemoryStream(input))
            using (var outputStream = new System.IO.MemoryStream(input.Length))
            {
                var buffer = new byte[64];
                var output = new byte[64];
                var block = new uint[16];
                var length = 0;
                while ((length = inputStream.Read(buffer, 0, 64)) > 0)
                {
                    SalsaBlock(block, state);

                    for (var i = 0; i < block.Length; i++)
                    {
                        var value = block[i];
                        output[i * 4] = (byte)(value & 0xff);
                        output[i * 4 + 1] = (byte)((value >> 8) & 0xff);
                        output[i * 4 + 2] = (byte)((value >> 16) & 0xff);
                        output[i * 4 + 3] = (byte)((value >> 24) & 0xff);
                    }

                    for (var i = 0; i < length; i++)
                    {
                        outputStream.WriteByte((byte)(buffer[i] ^ output[i]));
                    }

                    ulong count = 1;
                    count += ((ulong)state[9] << 32) | (ulong)state[8];
                    state[8] = (uint)(count & 0xffff_ffff);
                    state[9] = (uint)((count >> 32) & 0xffff_ffff);
                }

                return outputStream.GetBuffer();
            }
        }

        public static byte[] Encode(byte[] input, byte[] key, byte[] nonce)
        {
            var subNonce = new byte[16];
            if (nonce.Length == 24)
            {
                var hNonce = new byte[16];
                System.Buffer.BlockCopy(nonce, 0, hNonce, 0, 16);
                System.Buffer.BlockCopy(nonce, 16, subNonce, 0, 8);
                key = HSalsa20.Encode(key, hNonce);
            }
            else if (nonce.Length == 8)
            {
                System.Buffer.BlockCopy(nonce, 0, subNonce, 0, 8);
            }
            else
            {
                throw new System.ArgumentException();

            }

            return NormalEncode(input, key, subNonce);
        }
    }
}
