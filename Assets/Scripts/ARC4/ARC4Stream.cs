using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Crypto
{
    public class ARC4Stream : Stream
    {

        private static byte[] s_S = new byte[256];

        static ARC4Stream()
        {
            for (var i = 0; i < 256; i++)
            {
                s_S[i] = (byte)i;
            }
        }

        private Stream m_baseStream;

        private byte[] m_key;

        public override bool CanRead => this.m_baseStream.CanRead;

        public override bool CanSeek => this.m_baseStream.CanSeek;

        public override bool CanWrite => this.m_baseStream.CanWrite;

        public override long Length => this.m_baseStream.Length;

        public override long Position { get => this.m_baseStream.Position; set => this.m_baseStream.Position = value; }

        public ARC4Stream(Stream stream, byte[] key)
        {
            this.m_baseStream = stream;
            this.m_key = key;
        }

        public override void Flush()
        {
            this.m_baseStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var ret = this.m_baseStream.Read(buffer, offset, count);
            this.Encode(buffer, offset, count);

            return ret;
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
            this.Encode(buffer, offset, count);
            this.m_baseStream.Write(buffer, offset, count);
        }

        private byte[] KSA(byte[] key)
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

        private void Encode(byte[] buffer, int offset, int count)
        {
            var s = KSA(this.m_key);
            var i = offset;
            var j = 0;

            for (var index = offset; index < count; index++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
                var k = s[(s[i] + s[j]) % 256];

                buffer[index] = (byte)(buffer[index] ^ k);
            }
        }
    }
}
