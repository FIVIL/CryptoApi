using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptoApi
{
    class ShortMessageRsa
    {
        private KeyContainer KeyPair { get; set; }
        public string PublicKeyS { get => KeyPair.PublicKeyS; }
        public byte[] PublicKey { get => KeyPair.PublicKey; }
        #region ctor
        /// <summary>
        /// First Use For Creating Wallet
        /// </summary>
        public ShortMessageRsa()
        {
            KeyPair = new KeyContainer();
        }
        /// <summary>
        /// for client inorder to encrypt
        /// </summary>
        /// <param name="filename">private key file path</param>
        public ShortMessageRsa(string filename)
        {
            KeyPair = new KeyContainer(filename);
        }
        /// <summary>
        /// for server inorder to decrypt
        /// </summary>
        /// <param name="publickey">public key</param>
        public ShortMessageRsa(byte[] publickey)
        {
            KeyPair = new KeyContainer(publickey);
        }
        #endregion
        public string Encrypt(string message)
        {
            var byt = Encoding.UTF8.GetBytes(message);
            return Convert.ToBase64String(KeyPair.Rsa.Encrypt(byt, false));
        }
        public string Decrypt(string message)
        {
            var byt = Convert.FromBase64String(message);
            return Encoding.UTF8.GetString(KeyPair.Rsa.Decrypt(byt, false));
        }
        public void ExportKey(string filepath)
        {
            KeyPair.ExportPrivateKey(filepath);
        }
    }
}
