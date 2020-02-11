// #define ROTL(a, b) ((a << b) | (a >> (32 - b)))

// #define QR(a, b, c, d) b ^= ROTL((a + d), 7);\
// c ^= ROTL((b + a), 9);\
// d ^= ROTL((c + b), 13);\
// a ^= ROTL((d + c), 18)\

// #define UIntToByte(value, a, b, c, d) a = (byte)(value & 0xff);\
//                                       b = (byte) ((value >> 8) & 0xff);\
//                                       c = (byte) ((value >> 16) & 0xff);\
//                                       d = (byte) ((value >> 24) & 0xff);\

using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace Crypto
{
    public static class HSalsa20
    {
        private const int ROUNDS = 20;

        public static byte[] Encode(byte[] key, byte[] nonce)
        {
            var output = new byte[32];
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

            for (var i = 0; i < ROUNDS; i += 2)
            {
                state[4] ^= (((state[0] + state[12]) << 7) | ((state[0] + state[12]) >> (32 - 7)));
                state[8] ^= (((state[4] + state[0]) << 9) | ((state[4] + state[0]) >> (32 - 9)));
                state[12] ^= (((state[8] + state[4]) << 13) | ((state[8] + state[4]) >> (32 - 13)));
                state[0] ^= (((state[12] + state[8]) << 18) | ((state[12] + state[8]) >> (32 - 18)));

                state[9] ^= (((state[5] + state[1]) << 7) | ((state[5] + state[1]) >> (32 - 7)));
                state[13] ^= (((state[9] + state[5]) << 9) | ((state[9] + state[5]) >> (32 - 9)));
                state[1] ^= (((state[13] + state[9]) << 13) | ((state[13] + state[9]) >> (32 - 13)));
                state[5] ^= (((state[1] + state[13]) << 18) | ((state[1] + state[13]) >> (32 - 18)));

                state[14] ^= (((state[10] + state[6]) << 7) | ((state[10] + state[6]) >> (32 - 7)));
                state[2] ^= (((state[14] + state[10]) << 9) | ((state[14] + state[10]) >> (32 - 9)));
                state[6] ^= (((state[2] + state[14]) << 13) | ((state[2] + state[14]) >> (32 - 13)));
                state[10] ^= (((state[6] + state[2]) << 18) | ((state[6] + state[2]) >> (32 - 18)));

                state[3] ^= (((state[15] + state[11]) << 7) | ((state[15] + state[11]) >> (32 - 7)));
                state[7] ^= (((state[3] + state[15]) << 9) | ((state[3] + state[15]) >> (32 - 9)));
                state[11] ^= (((state[7] + state[3]) << 13) | ((state[7] + state[3]) >> (32 - 13)));
                state[15] ^= (((state[11] + state[7]) << 18) | ((state[11] + state[7]) >> (32 - 18)));

                state[1] ^= (((state[0] + state[3]) << 7) | ((state[0] + state[3]) >> (32 - 7)));
                state[2] ^= (((state[1] + state[0]) << 9) | ((state[1] + state[0]) >> (32 - 9)));
                state[3] ^= (((state[2] + state[1]) << 13) | ((state[2] + state[1]) >> (32 - 13)));
                state[0] ^= (((state[3] + state[2]) << 18) | ((state[3] + state[2]) >> (32 - 18)));

                state[6] ^= (((state[5] + state[4]) << 7) | ((state[5] + state[4]) >> (32 - 7)));
                state[7] ^= (((state[6] + state[5]) << 9) | ((state[6] + state[5]) >> (32 - 9)));
                state[4] ^= (((state[7] + state[6]) << 13) | ((state[7] + state[6]) >> (32 - 13)));
                state[5] ^= (((state[4] + state[7]) << 18) | ((state[4] + state[7]) >> (32 - 18)));

                state[11] ^= (((state[10] + state[9]) << 7) | ((state[10] + state[9]) >> (32 - 7)));
                state[8] ^= (((state[11] + state[10]) << 9) | ((state[11] + state[10]) >> (32 - 9)));
                state[9] ^= (((state[8] + state[11]) << 13) | ((state[8] + state[11]) >> (32 - 13)));
                state[10] ^= (((state[9] + state[8]) << 18) | ((state[9] + state[8]) >> (32 - 18)));

                state[12] ^= (((state[15] + state[14]) << 7) | ((state[15] + state[14]) >> (32 - 7)));
                state[13] ^= (((state[12] + state[15]) << 9) | ((state[12] + state[15]) >> (32 - 9)));
                state[14] ^= (((state[13] + state[12]) << 13) | ((state[13] + state[12]) >> (32 - 13)));
                state[15] ^= (((state[14] + state[13]) << 18) | ((state[14] + state[13]) >> (32 - 18)));
            }

            output[0] = (byte)(state[0] & 0xff);
            output[1] = (byte)((state[0] >> 8) & 0xff);
            output[2] = (byte)((state[0] >> 16) & 0xff);
            output[3] = (byte)((state[0] >> 24) & 0xff);
            output[4] = (byte)(state[5] & 0xff);
            output[5] = (byte)((state[5] >> 8) & 0xff);
            output[6] = (byte)((state[5] >> 16) & 0xff);
            output[7] = (byte)((state[5] >> 24) & 0xff);
            output[8] = (byte)(state[10] & 0xff);
            output[9] = (byte)((state[10] >> 8) & 0xff);
            output[10] = (byte)((state[10] >> 16) & 0xff);
            output[11] = (byte)((state[10] >> 24) & 0xff);
            output[12] = (byte)(state[15] & 0xff);
            output[13] = (byte)((state[15] >> 8) & 0xff);
            output[14] = (byte)((state[15] >> 16) & 0xff);
            output[15] = (byte)((state[15] >> 24) & 0xff);

            output[16] = (byte)(state[6] & 0xff);
            output[17] = (byte)((state[6] >> 8) & 0xff);
            output[18] = (byte)((state[6] >> 16) & 0xff);
            output[19] = (byte)((state[6] >> 24) & 0xff);
            output[20] = (byte)(state[7] & 0xff);
            output[21] = (byte)((state[7] >> 8) & 0xff);
            output[22] = (byte)((state[7] >> 16) & 0xff);
            output[23] = (byte)((state[7] >> 24) & 0xff);
            output[24] = (byte)(state[8] & 0xff);
            output[25] = (byte)((state[8] >> 8) & 0xff);
            output[26] = (byte)((state[8] >> 16) & 0xff);
            output[27] = (byte)((state[8] >> 24) & 0xff);
            output[28] = (byte)(state[9] & 0xff);
            output[29] = (byte)((state[9] >> 8) & 0xff);
            output[30] = (byte)((state[9] >> 16) & 0xff);
            output[31] = (byte)((state[9] >> 24) & 0xff);

            return output;
        }
    }
}