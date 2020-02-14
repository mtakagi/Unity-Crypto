// https://ja.wikipedia.org/wiki/Salsa20#ChaCha

namespace Crypto
{
    public static class ChaCha20
    {
        private static uint ROTL(uint a, uint b) => ((a << (int)(b)) | (a >> (32 - (int)(b))));
        private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = ROTL(d, 16);
            c += d; b ^= c; b = ROTL(b, 12);
            a += b; d ^= a; d = ROTL(d, 8);
            c += d; b ^= c; b = ROTL(b, 7);
        }
        private const int ROUNDS = 20;

        private static void ChaChaBlock(uint[] output, uint[] input)
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
                QR(ref x[1], ref x[5], ref x[9], ref x[13]); // column 1
                QR(ref x[2], ref x[6], ref x[10], ref x[14]); // column 2
                QR(ref x[3], ref x[7], ref x[11], ref x[15]); // column 3
                // Even round
                QR(ref x[0], ref x[5], ref x[10], ref x[15]); // diagonal 1 (main diagonal)
                QR(ref x[1], ref x[6], ref x[11], ref x[12]); // diagonal 2
                QR(ref x[2], ref x[7], ref x[8], ref x[13]); // diagonal 3
                QR(ref x[3], ref x[4], ref x[9], ref x[14]); // diagonal 4
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
            state[1] = (uint)'n' | (uint)'d' << 8 | (uint)' ' << 16 | (uint)'3' << 24; // nd 3
            state[2] = (uint)'2' | (uint)'-' << 8 | (uint)'b' << 16 | (uint)'y' << 24; // 2-by
            state[3] = (uint)'t' | (uint)'e' << 8 | (uint)' ' << 16 | (uint)'k' << 24; // te k

            state[4] = (uint)key[0] | (uint)key[1] << 8 | (uint)key[2] << 16 | (uint)key[3] << 24;
            state[5] = (uint)key[4] | (uint)key[5] << 8 | (uint)key[6] << 16 | (uint)key[7] << 24;
            state[6] = (uint)key[8] | (uint)key[9] << 8 | (uint)key[10] << 16 | (uint)key[11] << 24;
            state[7] = (uint)key[12] | (uint)key[13] << 8 | (uint)key[14] << 16 | (uint)key[15] << 24;
            state[8] = (uint)key[16] | (uint)key[17] << 8 | (uint)key[18] << 16 | (uint)key[19] << 24;
            state[9] = (uint)key[20] | (uint)key[21] << 8 | (uint)key[22] << 16 | (uint)key[23] << 24;
            state[10] = (uint)key[24] | (uint)key[25] << 8 | (uint)key[26] << 16 | (uint)key[27] << 24;
            state[11] = (uint)key[28] | (uint)key[29] << 8 | (uint)key[30] << 16 | (uint)key[31] << 24;

            state[12] = 0;
            state[13] = (uint)nonce[0] | (uint)nonce[1] << 8 | (uint)nonce[2] << 16 | (uint)nonce[3] << 24;
            state[14] = (uint)nonce[4] | (uint)nonce[5] << 8 | (uint)nonce[6] << 16 | (uint)nonce[7] << 24;
            state[15] = (uint)nonce[8] | (uint)nonce[9] << 8 | (uint)nonce[10] << 16 | (uint)nonce[11] << 24;

            using (var inputStream = new System.IO.MemoryStream(input))
            using (var outputStream = new System.IO.MemoryStream(input.Length))
            {
                var buffer = new byte[64];
                var output = new byte[64];
                var block = new uint[16];
                var length = 0;
                while ((length = inputStream.Read(buffer, 0, 64)) > 0)
                {
                    ChaChaBlock(block, state);

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

                    state[12] += 1;

                    // ulong count = 1;
                    // count += ((ulong)state[13] << 32) | (ulong)state[12];
                    // state[12] = (uint)(count & 0xffff_ffff);
                    // state[13] = (uint)((count >> 32) & 0xffff_ffff);
                }

                return outputStream.GetBuffer();
            }
        }

        public static byte[] Encode(byte[] input, byte[] key, byte[] nonce)
        {
            var subNonce = new byte[12];
            if (nonce.Length == 24)
            {
                var hNonce = new byte[16];
                System.Buffer.BlockCopy(nonce, 0, hNonce, 0, 16);
                System.Buffer.BlockCopy(nonce, 16, subNonce, 4, 8);
                key = HChaCha20.Encode(key, hNonce);
            }
            else if (nonce.Length == 12)
            {
                System.Buffer.BlockCopy(nonce, 0, subNonce, 0, 12);
            }
            else
            {
                throw new System.ArgumentException();

            }

            return NormalEncode(input, key, subNonce);
        }
    }
}
