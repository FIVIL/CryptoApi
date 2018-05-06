using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoApi
{
    public class Signture
    {
        public byte[] Data { get; private set; }
        public string Value { get;private set; }
        public Signture(byte[] data)
        {
            Data = data;
            Value = Convert.ToBase64String(data);
        }
        public override string ToString()
        {
            return Value;
        }
        public static implicit operator byte[](Signture s)
        {
            return s.Data;
        }
    }
}
