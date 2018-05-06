using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptoApi
{
    class KeyContainer
    {
        private byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; private set; }
        public string PublicKeyS { get; private set; }
        public RSACryptoServiceProvider Rsa { get; private set; }
        public KeyContainer()
        {
            Rsa = new RSACryptoServiceProvider();
            PrivateKey = Rsa.ExportCspBlob(true);
            PublicKey = Rsa.ExportCspBlob(false);
            PublicKeyS = Convert.ToBase64String(PublicKey);
        }
        public KeyContainer(string filepath)
        {
            PrivateKey = EncryptedFileWriter.ReadFile(filepath);
            Rsa = new RSACryptoServiceProvider();
            Rsa.ImportCspBlob(PrivateKey);
            PrivateKey = Rsa.ExportCspBlob(true);
            PublicKey = Rsa.ExportCspBlob(false);
            PublicKeyS = Convert.ToBase64String(PublicKey);
        }
        public KeyContainer(byte[] publickey)
        {
            PublicKey = publickey;
            Rsa = new RSACryptoServiceProvider();
            Rsa.ImportCspBlob(PublicKey);
            PublicKey = Rsa.ExportCspBlob(false);
            PublicKeyS = Convert.ToBase64String(PublicKey);
        }
        public void ExportPrivateKey(string filename)
        {
            if (Rsa.PublicOnly) throw new Exception("no private key!");
            EncryptedFileWriter.WriteFile(PrivateKey, filename);
        }
    }
}
