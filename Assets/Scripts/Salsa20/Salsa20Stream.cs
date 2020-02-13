using System;
using System.IO;

namespace Crypto
{
    public class Salsa20Stream : Stream
    {
        private Stream m_baseStream;
        private byte[] m_key;
        private byte[] m_nonce;


        public Salsa20Stream(Stream stream, byte[] key, byte[] nonce)
        {
            this.m_nonce = new byte[16];
            if (nonce.Length == 24)
            {
                var hNonce = new byte[16];
                System.Buffer.BlockCopy(nonce, 0, hNonce, 0, 16);
                System.Buffer.BlockCopy(nonce, 16, this.m_nonce, 0, 8);
                key = HSalsa20.Encode(key, hNonce);
            }
            else if (nonce.Length == 8)
            {
                System.Buffer.BlockCopy(nonce, 0, m_nonce, 0, 8);
            }
            else
            {
                throw new System.ArgumentException();
            }
            m_baseStream = stream;
            m_key = key;
        }

        public Salsa20Stream(byte[] input, byte[] key, byte[] nonce) : this(new MemoryStream(input), key, nonce)
        {
        }

        public override bool CanRead => this.m_baseStream.CanRead;

        public override bool CanSeek => this.m_baseStream.CanSeek;

        public override bool CanWrite => this.m_baseStream.CanWrite;

        public override long Length => this.m_baseStream.Length;

        public override long Position { get => this.m_baseStream.Position; set => this.m_baseStream.Position = value; }

        public override void Close()
        {
            base.Close();
        }

        public override void Flush()
        {
            this.m_baseStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var pos = this.Position;
            var size = this.m_baseStream.Read(buffer, offset, count);
            this.Encode(buffer, offset, count, pos);

            return size;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return this.m_baseStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            this.m_baseStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.Encode(buffer, offset, count, this.Position);
            this.m_baseStream.Write(buffer, offset, count);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

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

        private void Encode(byte[] input, int offset, int count, long position)
        {
            var state = new uint[16];
            var blockCounter = position / 64;
            var keyPosition = position % 64;
            var init = false;
            var output = new byte[64];

            state[0] = (uint)'e' | (uint)'x' << 8 | (uint)'p' << 16 | (uint)'a' << 24; // expa
            state[5] = (uint)'n' | (uint)'d' << 8 | (uint)' ' << 16 | (uint)'3' << 24; // nd 3
            state[10] = (uint)'2' | (uint)'-' << 8 | (uint)'b' << 16 | (uint)'y' << 24; // 2-by
            state[15] = (uint)'t' | (uint)'e' << 8 | (uint)' ' << 16 | (uint)'k' << 24; // te k

            state[1] = (uint)this.m_key[0] | (uint)this.m_key[1] << 8 | (uint)this.m_key[2] << 16 | (uint)this.m_key[3] << 24;
            state[2] = (uint)this.m_key[4] | (uint)this.m_key[5] << 8 | (uint)this.m_key[6] << 16 | (uint)this.m_key[7] << 24;
            state[3] = (uint)this.m_key[8] | (uint)this.m_key[9] << 8 | (uint)this.m_key[10] << 16 | (uint)this.m_key[11] << 24;
            state[4] = (uint)this.m_key[12] | (uint)this.m_key[13] << 8 | (uint)this.m_key[14] << 16 | (uint)this.m_key[15] << 24;
            state[11] = (uint)this.m_key[16] | (uint)this.m_key[17] << 8 | (uint)this.m_key[18] << 16 | (uint)this.m_key[19] << 24;
            state[12] = (uint)this.m_key[20] | (uint)this.m_key[21] << 8 | (uint)this.m_key[22] << 16 | (uint)this.m_key[23] << 24;
            state[13] = (uint)this.m_key[24] | (uint)this.m_key[25] << 8 | (uint)this.m_key[26] << 16 | (uint)this.m_key[27] << 24;
            state[14] = (uint)this.m_key[28] | (uint)this.m_key[29] << 8 | (uint)this.m_key[30] << 16 | (uint)this.m_key[31] << 24;

            state[6] = (uint)this.m_nonce[0] | (uint)this.m_nonce[1] << 8 | (uint)this.m_nonce[2] << 16 | (uint)this.m_nonce[3] << 24;
            state[7] = (uint)this.m_nonce[4] | (uint)this.m_nonce[5] << 8 | (uint)this.m_nonce[6] << 16 | (uint)this.m_nonce[7] << 24;
            state[8] = (uint)(blockCounter & 0xffff_ffff);
            state[9] = (uint)((blockCounter >> 32) & 0xffff_ffff);

            for (var i = offset; i < count; i++)
            {
                if (!init || (keyPosition % 64) == 0)
                {
                    var block = new uint[16];
                    SalsaBlock(block, state);

                    for (var j = 0; j < block.Length; j++)
                    {
                        var value = block[j];
                        output[j * 4] = (byte)(value & 0xff);
                        output[j * 4 + 1] = (byte)((value >> 8) & 0xff);
                        output[j * 4 + 2] = (byte)((value >> 16) & 0xff);
                        output[j * 4 + 3] = (byte)((value >> 24) & 0xff);
                    }

                    if (init) keyPosition = 0;
                    init = true;

                    ulong counter = 1;
                    counter += ((ulong)state[9] << 32) | (ulong)state[8];
                    state[8] = (uint)(counter & 0xffff_ffff);
                    state[9] = (uint)((counter >> 32) & 0xffff_ffff);
                }
                input[i] ^= output[keyPosition];

                keyPosition++;
            }
        }
    }
}
