using System.Collections;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using UnityEngine;
using UnityEngine.TestTools;

namespace Tests
{
    public class Salsa20Test
    {
        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length / 2)
                             .Select(x => System.Convert.ToByte(hex.Substring(x * 2, 2), 16))
                             .ToArray();
        }

        // A Test behaves as an ordinary method
        [Test]
        public void HSalsa20TestSimplePasses()
        {
            var nonce = System.Text.Encoding.UTF8.GetBytes("24-byte nonce for xsalsa");
            var key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20");
            var result = new byte[] { 151, 205, 12, 216, 173, 8, 22, 3, 82, 0, 130, 153, 243, 61, 237, 44, 110, 110, 17, 200, 91, 58, 29, 149, 216, 199, 197, 236, 50, 75, 36, 113 };
            var hnonce = new byte[16];
            System.Buffer.BlockCopy(nonce, 0, hnonce, 0, 16);
            var output = Crypto.HSalsa20.Encode(key, hnonce);

            Assert.AreEqual(result, output);
        }

        [Test]
        public void HSalsa20TestPasses()
        {
            var list = new[]{
                new {
                    message = System.Text.Encoding.UTF8.GetBytes("Hello world!"),
                    nonce = System.Text.Encoding.UTF8.GetBytes("24-byte nonce for xsalsa"),
                    key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20"),
                    result = new byte[] { 0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41 },
                },
                new {
                    message = new byte[64],
                    nonce = System.Text.Encoding.UTF8.GetBytes("24-byte nonce for xsalsa"),
                    key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20"),
                    result = new byte[] {
                        0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f, 0xb6,
                        0x6d, 0x81, 0x60, 0x9b, 0xd5, 0x47, 0xfa, 0xbc, 0xbe, 0x70,
                        0x26, 0xed, 0xc8, 0xb5, 0xe5, 0xe4, 0x49, 0xd0, 0x88, 0xbf,
                        0xa6, 0x9c, 0x08, 0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26,
                        0x7c, 0x2c, 0x19, 0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b, 0x40,
                        0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51, 0xec, 0x26, 0x5f,
                        0x3a, 0x58, 0xe4, 0x76, 0x48},
                },
            };

            foreach (var item in list)
            {
                var result = Crypto.Salsa20.Encode(item.message, item.key, item.nonce);
                Assert.AreEqual(result, item.result);
            }
        }

        [Test]
        public void HSalsa20StreamTestPasses()
        {
            var list = new[]{
                new {
                    message = System.Text.Encoding.UTF8.GetBytes("Hello world!"),
                    nonce = System.Text.Encoding.UTF8.GetBytes("24-byte nonce for xsalsa"),
                    key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20"),
                    result = new byte[] { 0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41 },
                },
                new {
                    message = new byte[64],
                    nonce = System.Text.Encoding.UTF8.GetBytes("24-byte nonce for xsalsa"),
                    key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20"),
                    result = new byte[] {
                        0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f, 0xb6,
                        0x6d, 0x81, 0x60, 0x9b, 0xd5, 0x47, 0xfa, 0xbc, 0xbe, 0x70,
                        0x26, 0xed, 0xc8, 0xb5, 0xe5, 0xe4, 0x49, 0xd0, 0x88, 0xbf,
                        0xa6, 0x9c, 0x08, 0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26,
                        0x7c, 0x2c, 0x19, 0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b, 0x40,
                        0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51, 0xec, 0x26, 0x5f,
                        0x3a, 0x58, 0xe4, 0x76, 0x48},
                },
            };

            foreach (var item in list)
            {
                using (var stream = new Crypto.Salsa20Stream(item.message, item.key, item.nonce))
                {
                    var result = new byte[item.message.Length];

                    stream.Read(result, 0, item.message.Length);
                    Assert.AreEqual(result, item.result);
                }
            }
        }

        // A Test behaves as an ordinary method
        [Test]
        public void Salsa20TestSimplePasses()
        {
            var message = System.Text.Encoding.UTF8.GetBytes("Hello world!");
            var nonce = System.Text.Encoding.UTF8.GetBytes("8byte no");
            var key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20");
            var output = Crypto.Salsa20.Encode(message, key, nonce);

            Assert.AreEqual(output, new byte[] { 65, 157, 224, 202, 47, 78, 178, 37, 154, 212, 145, 82 });
        }

        [Test]
        public void Salsa20TestPaasses()
        {
            var list = new[] {
                new {
                    key = StringToByteArray("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
                    nonce = StringToByteArray("0D74DB42A91077DE"),
                    length = 131072,
                    xor = StringToByteArray("C349B6A51A3EC9B712EAED3F90D8BCEE69B7628645F251A996F55260C62EF31FD6C6B0AEA94E136C9D984AD2DF3578F78E457527B03A0450580DD874F63B1AB9"),
                },
                new {
                    key = StringToByteArray("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
                    nonce = StringToByteArray("167DE44BB21980E7"),
                    length = 131072,
                    xor = StringToByteArray("C3EAAF32836BACE32D04E1124231EF47E101367D6305413A0EEB07C60698A2876E4D031870A739D6FFDDD208597AFF0A47AC17EDB0167DD67EBA84F1883D4DFD"),
                },
                new {
                    key = StringToByteArray("0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417"),
                    nonce = StringToByteArray("1F86ED54BB2289F0"),
                    length = 131072,
                    xor = StringToByteArray("3CD23C3DC90201ACC0CF49B440B6C417F0DC8D8410A716D5314C059E14B1A8D9A9FB8EA3D9C8DAE12B21402F674AA95C67B1FC514E994C9D3F3A6E41DFF5BBA6"),
                },
                new {
                    key = StringToByteArray("0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C"),
                    nonce = StringToByteArray("288FF65DC42B92F9"),
                    length = 131072,
                    xor = StringToByteArray("E00EBCCD70D69152725F9987982178A2E2E139C7BCBE04CA8A0E99E318D9AB76F988C8549F75ADD790BA4F81C176DA653C1A043F11A958E169B6D2319F4EEC1A"),
                },
            };

            foreach (var item in list)
            {
                var input = new byte[item.length];
                var output = Crypto.Salsa20.Encode(input, item.key, item.nonce);
                var result = new byte[64];
                var buffer = new byte[64];

                for (var i = 0; i < item.length; i += 64)
                {
                    System.Buffer.BlockCopy(output, i, buffer, 0, 64);

                    for (var j = 0; j < 64; j++)
                    {
                        result[j] ^= buffer[j];
                    }
                }

                Assert.AreEqual(result, item.xor);
            }
        }

        [Test]
        public void Salsa20StreamTestPaasses()
        {
            var list = new[] {
                new {
                    key = StringToByteArray("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
                    nonce = StringToByteArray("0D74DB42A91077DE"),
                    length = 131072,
                    xor = StringToByteArray("C349B6A51A3EC9B712EAED3F90D8BCEE69B7628645F251A996F55260C62EF31FD6C6B0AEA94E136C9D984AD2DF3578F78E457527B03A0450580DD874F63B1AB9"),
                },
                new {
                    key = StringToByteArray("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
                    nonce = StringToByteArray("167DE44BB21980E7"),
                    length = 131072,
                    xor = StringToByteArray("C3EAAF32836BACE32D04E1124231EF47E101367D6305413A0EEB07C60698A2876E4D031870A739D6FFDDD208597AFF0A47AC17EDB0167DD67EBA84F1883D4DFD"),
                },
                new {
                    key = StringToByteArray("0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417"),
                    nonce = StringToByteArray("1F86ED54BB2289F0"),
                    length = 131072,
                    xor = StringToByteArray("3CD23C3DC90201ACC0CF49B440B6C417F0DC8D8410A716D5314C059E14B1A8D9A9FB8EA3D9C8DAE12B21402F674AA95C67B1FC514E994C9D3F3A6E41DFF5BBA6"),
                },
                new {
                    key = StringToByteArray("0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C"),
                    nonce = StringToByteArray("288FF65DC42B92F9"),
                    length = 131072,
                    xor = StringToByteArray("E00EBCCD70D69152725F9987982178A2E2E139C7BCBE04CA8A0E99E318D9AB76F988C8549F75ADD790BA4F81C176DA653C1A043F11A958E169B6D2319F4EEC1A"),
                },
            };

            foreach (var item in list)
            {
                var input = new byte[item.length];
                var stream = new Crypto.Salsa20Stream(input, item.key, item.nonce);
                var output = new byte[item.length];
                stream.Read(output, 0, item.length);
                var result = new byte[64];
                var buffer = new byte[64];

                for (var i = 0; i < item.length; i += 64)
                {
                    System.Buffer.BlockCopy(output, i, buffer, 0, 64);

                    for (var j = 0; j < 64; j++)
                    {
                        result[j] ^= buffer[j];
                    }
                }

                Assert.AreEqual(result, item.xor);
            }
        }

        [Test]
        public void Salsa20StreamTestSimplePasses()
        {
            var message = System.Text.Encoding.UTF8.GetBytes("Hello world!");
            var nonce = System.Text.Encoding.UTF8.GetBytes("8byte no");
            var key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20");
            var stream = new Crypto.Salsa20Stream(message, key, nonce);
            var output = new byte[message.Length];

            stream.Read(output, 0, message.Length);
            Assert.AreEqual(output, new byte[] { 65, 157, 224, 202, 47, 78, 178, 37, 154, 212, 145, 82 });
        }

        [Test]
        public void Salsa20StreamTestSimpleDecryptPasses()
        {
            var message = new byte[] { 65, 157, 224, 202, 47, 78, 178, 37, 154, 212, 145, 82 };
            var nonce = System.Text.Encoding.UTF8.GetBytes("8byte no");
            var key = System.Text.Encoding.UTF8.GetBytes("this is 32-byte key for xsalsa20");
            var stream = new Crypto.Salsa20Stream(message, key, nonce);
            var output = new byte[message.Length];

            stream.Read(output, 0, message.Length);
            Assert.AreEqual(output, System.Text.Encoding.UTF8.GetBytes("Hello world!"));
        }
    }
}
