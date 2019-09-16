using System;
using System.IO;
using System.Linq;

namespace IPSReader {

    class Program {
        private const string Format = "Put(0x{0}, Blob.FromHex(\"{1}\"));";
        static int Main(string[] args)
        {
            // Test if input arguments were supplied:
            if (args.Length == 0)
            {
                Console.WriteLine("usage: ips_to_ffr.exe <filename>");
                return 1;
            }

            string fileName = args[0];
            DisplayValues(fileName);
            return 0;
        }

        public static string Hexify(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }
        public static void DisplayValues(string fileName)
        {
            if (File.Exists(fileName))
            {
                using (BinaryReader reader = new BinaryReader(File.Open(fileName, FileMode.Open, FileAccess.Read)))
                {
                    // We don't actually *do* anything with the header but this is needed to seek to the first offset record
                    // See https://zerosoft.zophar.net/ips.php for a description of the IPS file format
                    byte[] header = reader.ReadBytes(5);
                    byte[] offset = reader.ReadBytes(3);

                    byte[] EOF = { 0x45, 0x4F, 0x46 };

                    while (!Enumerable.SequenceEqual(offset, EOF))
                    {
                        //Console.WriteLine("IPS Offset: " + Hexify(offset));

                        byte[] dl = reader.ReadBytes(2);

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(dl);
                        }

                        int n = BitConverter.ToUInt16(dl, 0);
                        //Console.WriteLine("Data length: {0}", n);

                        byte[] data = new byte[n];
                        data = reader.ReadBytes(n);

                        //Console.WriteLine(value: "Data: " + Hexify(data) + "\n");

                        // FFR offsets are 0x10 bytes behind where the data is in the final ROM due to header data.
                        // Therefore we subtract 0x10 from the offset address in the patch and then cast back to a byte value.
                        offset[2] = (byte)(offset[2] - 0x10);
                        Console.WriteLine(Format, Hexify(offset), Hexify(data));
                        offset = reader.ReadBytes(3);
                    }
                }
            }
        }
    }
}