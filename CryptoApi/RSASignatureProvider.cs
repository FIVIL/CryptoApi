using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptoApi
{
    public class RSASignatureProvider
    {

        private RSAPKCS1SignatureFormatter RSAFormatter { get; set; }
        private RSAPKCS1SignatureDeformatter RSADeformatter { get; set; }
        private KeyContainer KeyPair { get; set; }
        public string PublicKeyS { get => KeyPair.PublicKeyS; }
        public byte[] PublicKey { get => KeyPair.PublicKey; }
        private SHA256 Sha256 { get; set; }
        #region cotor
        /// <summary>
        /// First Use For Creating Wallet
        /// </summary>
        public RSASignatureProvider()
        {
            KeyPair = new KeyContainer();
            RSAFormatter = new RSAPKCS1SignatureFormatter(KeyPair.Rsa);
            Sha256 = SHA256.Create();
            RSAFormatter.SetHashAlgorithm("SHA256");
            RSADeformatter = new RSAPKCS1SignatureDeformatter(KeyPair.Rsa);
            RSADeformatter.SetHashAlgorithm("SHA256");
        }
        /// <summary>
        /// for using wallet and sending transaction
        /// </summary>
        /// <param name="filename">private key file path</param>
        public RSASignatureProvider(string filename)
        {
            KeyPair = new KeyContainer(filename);
            RSAFormatter = new RSAPKCS1SignatureFormatter(KeyPair.Rsa);
            Sha256 = SHA256.Create();
            RSAFormatter.SetHashAlgorithm("SHA256");
            RSADeformatter = new RSAPKCS1SignatureDeformatter(KeyPair.Rsa);
            RSADeformatter.SetHashAlgorithm("SHA256");
        }
        /// <summary>
        /// for miners inorder to verify signture using public key
        /// </summary>
        /// <param name="publickey">public key</param>
        public RSASignatureProvider(byte[] publickey)
        {
            KeyPair = new KeyContainer(publickey);
            RSADeformatter = new RSAPKCS1SignatureDeformatter(KeyPair.Rsa);
            Sha256 = SHA256.Create();
            RSADeformatter.SetHashAlgorithm("SHA256");
        }
        #endregion
        #region Create Signture
        public Signture CreateSignture(byte[] data)
        {
            var hash = Sha256.ComputeHash(data);
            return new Signture(RSAFormatter.CreateSignature(hash));
        }
        public Signture CreateSigntureASCII(string data)
        {
            var hash = Sha256.ComputeHash(Encoding.ASCII.GetBytes(data));
            return new Signture(RSAFormatter.CreateSignature(hash));
        }
        public Signture CreateSigntureUnicode(string data)
        {
            var hash = Sha256.ComputeHash(Encoding.Unicode.GetBytes(data));
            return new Signture(RSAFormatter.CreateSignature(hash));
        }
        #endregion
        #region Verify Signature
        public bool VerifySignature(byte[] data, Signture sign)
        {
            var hash = Sha256.ComputeHash(data);
            return RSADeformatter.VerifySignature(hash, sign);
        }
        public bool VerifySignatureASCII(string data, Signture sign)
        {
            var hash = Sha256.ComputeHash(Encoding.ASCII.GetBytes(data));
            return RSADeformatter.VerifySignature(hash, sign);
        }
        public bool VerifySignatureUnicode(string data, Signture sign)
        {
            var hash = Sha256.ComputeHash(Encoding.Unicode.GetBytes(data));
            return RSADeformatter.VerifySignature(hash, sign);
        }
        #endregion
        public void ExportPrivateKey(string filepath)
        {
            KeyPair.ExportPrivateKey(filepath);
        }
    }
}
