namespace Crypto
{
    public static class HChaCha20
    {
        private const int ROUNDS = 20;

        private static uint ROTL(uint a, uint b) => ((a << (int)(b)) | (a >> (32 - (int)(b))));

        private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = ROTL(d, 16);
            c += d; b ^= c; b = ROTL(b, 12);
            a += b; d ^= a; d = ROTL(d, 8);
            c += d; b ^= c; b = ROTL(b, 7);
        }

        public static byte[] Encode(byte[] key, byte[] nonce)
        {
            var output = new byte[32];
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

            state[12] = (uint)nonce[0] | (uint)nonce[1] << 8 | (uint)nonce[2] << 16 | (uint)nonce[3] << 24;
            state[13] = (uint)nonce[4] | (uint)nonce[5] << 8 | (uint)nonce[6] << 16 | (uint)nonce[7] << 24;
            state[14] = (uint)nonce[8] | (uint)nonce[9] << 8 | (uint)nonce[10] << 16 | (uint)nonce[11] << 24;
            state[15] = (uint)nonce[12] | (uint)nonce[13] << 8 | (uint)nonce[14] << 16 | (uint)nonce[15] << 24;

            for (var i = 0; i < ROUNDS; i += 2)
            {
                QR(ref state[0], ref state[4], ref state[8], ref state[12]); // column 0
                QR(ref state[1], ref state[5], ref state[9], ref state[13]); // column 1
                QR(ref state[2], ref state[6], ref state[10], ref state[14]); // column 2
                QR(ref state[3], ref state[7], ref state[11], ref state[15]); // column 3
                // Even round
                QR(ref state[0], ref state[5], ref state[10], ref state[15]); // diagonal 1 (main diagonal)
                QR(ref state[1], ref state[6], ref state[11], ref state[12]); // diagonal 2
                QR(ref state[2], ref state[7], ref state[8], ref state[13]); // diagonal 3
                QR(ref state[3], ref state[4], ref state[9], ref state[14]); // diagonal 4
            }

            output[0] = (byte)(state[0] & 0xff);
            output[1] = (byte)((state[0] >> 8) & 0xff);
            output[2] = (byte)((state[0] >> 16) & 0xff);
            output[3] = (byte)((state[0] >> 24) & 0xff);
            output[4] = (byte)(state[1] & 0xff);
            output[5] = (byte)((state[1] >> 8) & 0xff);
            output[6] = (byte)((state[1] >> 16) & 0xff);
            output[7] = (byte)((state[1] >> 24) & 0xff);
            output[8] = (byte)(state[2] & 0xff);
            output[9] = (byte)((state[2] >> 8) & 0xff);
            output[10] = (byte)((state[2] >> 16) & 0xff);
            output[11] = (byte)((state[2] >> 24) & 0xff);
            output[12] = (byte)(state[3] & 0xff);
            output[13] = (byte)((state[3] >> 8) & 0xff);
            output[14] = (byte)((state[3] >> 16) & 0xff);
            output[15] = (byte)((state[3] >> 24) & 0xff);

            output[16] = (byte)(state[12] & 0xff);
            output[17] = (byte)((state[12] >> 8) & 0xff);
            output[18] = (byte)((state[12] >> 16) & 0xff);
            output[19] = (byte)((state[12] >> 24) & 0xff);
            output[20] = (byte)(state[13] & 0xff);
            output[21] = (byte)((state[13] >> 8) & 0xff);
            output[22] = (byte)((state[13] >> 16) & 0xff);
            output[23] = (byte)((state[13] >> 24) & 0xff);
            output[24] = (byte)(state[14] & 0xff);
            output[25] = (byte)((state[14] >> 8) & 0xff);
            output[26] = (byte)((state[14] >> 16) & 0xff);
            output[27] = (byte)((state[14] >> 24) & 0xff);
            output[28] = (byte)(state[15] & 0xff);
            output[29] = (byte)((state[15] >> 8) & 0xff);
            output[30] = (byte)((state[15] >> 16) & 0xff);
            output[31] = (byte)((state[15] >> 24) & 0xff);

            return output;
        }
    }
}