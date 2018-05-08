using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptoApi
{
    public class ShortMessageRsa:IDisposable
    {
        private KeyContainer KeyPair { get; set; }
        public string PublicKeyS { get => KeyPair.PublicKeyS; }
        public byte[] PublicKey { get => KeyPair.PublicKey; }
        #region cotor
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
            return Convert.ToBase64String(KeyPair.Rsa.Encrypt(byt,false));
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

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                    KeyPair.Dispose();
                    KeyPair = null;
                    GC.Collect();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~RsaEncryptionProvider() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}
