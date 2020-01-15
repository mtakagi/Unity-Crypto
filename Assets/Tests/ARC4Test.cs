using System.Collections;
using System.Collections.Generic;
using NUnit.Framework;
using UnityEngine;
using UnityEngine.TestTools;

namespace Tests
{
    public class ARC4Test
    {
        // A Test behaves as an ordinary method
        [Test]
        public void ARC4TestSimplePasses()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("hogehogehoge");
            var key = System.Text.Encoding.UTF8.GetBytes("fugafugafugafugafugafuga");
            var result = Crypto.ARC4.Encode(data, key);

            Assert.IsNotEmpty(result);

            var decrypt = System.Text.Encoding.UTF8.GetString(Crypto.ARC4.Encode(result, key));

            Assert.AreEqual(data, decrypt);
        }

        [Test]
        public void ARC4OpenSSLTest()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("hogehogehoge");
            var bytes = Resources.Load<TextAsset>("rc4_enc").bytes;
            var key = System.Text.Encoding.UTF8.GetBytes("fugafugafugafugafugafuga");
            var result = Crypto.ARC4.Encode(bytes, key);

            Assert.AreEqual(data, result);
        }

        [Test]
        public void ARC4LoremTest()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
            var bytes = Resources.Load<TextAsset>("lorem_enc").bytes;
            var key = System.Text.Encoding.UTF8.GetBytes("fugafugafugafugafugafuga");
            var result = Crypto.ARC4.Encode(bytes, key);

            Assert.AreEqual(data, result);
        }

        [Test]
        public void ARC4TestStreamPasses()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("hogehogehoge");
            var key = System.Text.Encoding.UTF8.GetBytes("fugafugafugafugafugafuga");
            var stream = new Crypto.ARC4Stream(new System.IO.MemoryStream(data), key);
            var buffer = new byte[data.Length];
            stream.Read(buffer, 0, buffer.Length);
            var result = Crypto.ARC4.Encode(data, key);

            Assert.AreEqual(buffer, result);
        }

        [Test]
        public void ARC4StreamOpenSSLTest()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("hogehogehoge");
            var bytes = Resources.Load<TextAsset>("rc4_enc").bytes;
            var key = System.Text.Encoding.UTF8.GetBytes("fugafugafugafugafugafuga");
            var stream = new Crypto.ARC4Stream(new System.IO.MemoryStream(bytes), key);
            var result = new byte[bytes.Length];

            stream.Read(result, 0, result.Length);

            Assert.AreEqual(data, result);
        }

        [Test]
        public void ARC4StreamLoremTest()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
            var bytes = Resources.Load<TextAsset>("lorem_enc").bytes;
            var key = System.Text.Encoding.UTF8.GetBytes("fugafugafugafugafugafuga");
            var stream = new Crypto.ARC4Stream(new System.IO.MemoryStream(bytes), key);
            var result = new byte[bytes.Length];

            stream.Read(result, 0, result.Length);

            Assert.AreEqual(data, result);
        }
    }
}
