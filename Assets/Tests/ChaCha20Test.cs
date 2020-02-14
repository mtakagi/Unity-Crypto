using System.Collections;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using UnityEngine;
using UnityEngine.TestTools;

namespace Tests
{
    public class ChaCha20Test
    {
        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length / 2)
                             .Select(x => System.Convert.ToByte(hex.Substring(x * 2, 2), 16))
                             .ToArray();
        }

        // draft-irtf-cfrg-xchacha-01
        [Test]
        public void XChaCha20TestPasses()
        {
            var list = new[]{
                new {
                    input = StringToByteArray("5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e"),
                    nonce = StringToByteArray("404142434445464748494a4b4c4d4e4f5051525354555658"),
                    key = StringToByteArray("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
                    output = StringToByteArray("4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5"),
                },
                new {
                    input = StringToByteArray("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                    nonce = StringToByteArray("c047548266b7c370d33566a2425cbf30d82d1eaf5294109e"),
                    key = StringToByteArray("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232"),
                    output = StringToByteArray("a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc"),
                },
            };

            foreach (var item in list)
            {
                var result = Crypto.ChaCha20.Encode(item.input, item.key, item.nonce);

                Assert.AreEqual(item.output, result);
            }
        }

        [Test]
        public void XChaCha20StreamTestPasses()
        {
            var list = new[]{
                new {
                    input = StringToByteArray("5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e"),
                    nonce = StringToByteArray("404142434445464748494a4b4c4d4e4f5051525354555658"),
                    key = StringToByteArray("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
                    output = StringToByteArray("4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5"),
                },
                new {
                    input = StringToByteArray("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                    nonce = StringToByteArray("c047548266b7c370d33566a2425cbf30d82d1eaf5294109e"),
                    key = StringToByteArray("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232"),
                    output = StringToByteArray("a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc"),
                },
            };

            foreach (var item in list)
            {
                using (var stream = new Crypto.ChaCha20Stream(item.input, item.key, item.nonce))
                {
                    var result = new byte[item.input.Length];

                    stream.Read(result, 0, item.input.Length);
                    Assert.AreEqual(item.output, result);
                }
            }
        }

        // A Test behaves as an ordinary method
        [Test]
        public void ChaCha20TestSimplePasses()
        {
            var message = StringToByteArray("23dbad0780");
            var nonce = StringToByteArray("ddfa69041ecc3feeb077cf45");
            var key = StringToByteArray("2be077349f80bf45faa1f427e81d90dbdc90a1d8d4212c1dacf2bd870000bfdf");
            var output = Crypto.ChaCha20.Encode(message, key, nonce);
            var expect = StringToByteArray("415a3e498d");

            Assert.AreEqual(expect, output);
        }

        [Test]
        public void ChaCha20StreamTestSimplePasses()
        {
            var message = StringToByteArray("23dbad0780");
            var nonce = StringToByteArray("ddfa69041ecc3feeb077cf45");
            var key = StringToByteArray("2be077349f80bf45faa1f427e81d90dbdc90a1d8d4212c1dacf2bd870000bfdf");
            var stream = new Crypto.ChaCha20Stream(message, key, nonce);
            var output = new byte[message.Length];
            var expect = StringToByteArray("415a3e498d");

            stream.Read(output, 0, output.Length);

            Assert.AreEqual(expect, output);
        }
    }
}
