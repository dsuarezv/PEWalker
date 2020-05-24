using Pastel;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Text;

namespace AuthentiPatcher
{
    class Program
    {
        static void Main(string[] args)
        { 
            if (args.Length == 0)
            {
                P.Warn("Usage: AuthentiPatch <command>");
                P.Info("  Available commands");
                P.Info("    print           Prints the PE header data");
                P.Info("    dump            dumps a part of the file, to file or to hex on output");
                P.Info("    patch           Patch parts of the executable");
                P.Info("    addAuthPayload  Adds a payload to the authenticode signature area");
                Console.WriteLine();
                return;
            }

            try
            {
                var command = args[0];

                switch (command.ToLower())
                {
                    case "print": HandlePrint(args); break;
                    case "dump": HandleDump(args); break;
                    case "patch": HandlePatch(args); break;
                    case "addauthpayload": HandleAddPayload(args); break;
                    default: throw new Exception($"Unknown command {command}");
                }
            }
            catch (Exception ex)
            { 
                P.Error(ex.Message);
            }
        }

        static void HandlePrint(string[] args)
        {
            if (args.Length != 2)
            {
                P.Info("print command usage");
                P.Info("  authentipatch print <filename>");
                return;
            }

            var inputFile = args[1];

            using (var parser = new PeParser(inputFile))
            {
                parser.Parse();
                PrintFields(parser.Fields);
            }
        }


        static void HandleDump(string[] args)
        {
            if (args.Length < 4)
            {
                P.Info("dump command usage");
                P.Info("  authentipatch dump <format> <offset> [size]");
                P.Info("    format can be any of:");
                P.Info("      raw  raw bytes printed to the output. Recomended redirection.");
                P.Info("      hex  00 4F 3B AB 00 44 01 0A  00 4F 3B AB 00 44 01 0A");
                P.Info("      sx   \\x00\\x4F\\x3B\\xAB\\x00\\x44\\x01\\x0A\\x00\\x4F\\x3B\\xAB\\x00\\x44\\x01\\x0A");
                P.Info("      zx   0x00,0x4F,0x3B,0xAB,0x00,0x44,0x01,0x0A,0x00,0x4F,0x3B,0xAB,0x00,0x44,0x01,0x0A");
                P.Info("    offset can be any of:");
                P.Info("      section name: .text  In this case size is not required");
                P.Info("      decimal value: 34563");
                P.Info("      hex value: 0x34A63");
                P.Info("");
                P.Info("Samples:");
                P.Info("  authentipatch dump sx .text");
                P.Info("  authentipatch dump hex .text");
                P.Info("  authentipatch dump raw 307200 0x345");
                return;
            }

            P.Error("Not implemented");
        }


        static void HandlePatch(string[] args)
        {
            if (args.Length != 4)
            {
                P.Info("patch command usage");
                P.Info("  authentipatch patch <inputfile> <offset> <content>");
                return;
            }

            P.Error("Not implemented");
        }


        static void HandleAddPayload(string[] args)
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
        

        // __ Patching ________________________________________________________


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


        // __ Print ___________________________________________________________


        static void PrintFields(IEnumerable<PeField> fields)
        {
            //string[] colors = new string[] { "#845EC2", "#D65DB1", "#FF6F91", "#FF9671", "#FFC75F", "#F9F871" };
            //string[] colors = new string[] { "#845EC2", "#4B4453", "#B0A8B9", "#00896F", "#00C0A3" };
            string[] colors = new string[] { "#845EC2", "#009EFA", "#00D2FC", "#4FFBDF" };
            int colorIndex = -1;


            PrintColoredLine(
                Right("OFFSET", 8) + ' ' +
                Left("GROUP", 20) +
                Left("TYPE", 6) +
                Left("NAME", 35) +
                Right("VALUE(hex)", 9) +
                ' ' + "COMMENT"
                , "FFFFFF");

            string lastGroup = null;

            foreach (var f in fields)
            {
                if (f.Group != lastGroup)
                {
                    lastGroup = f.Group;
                    colorIndex++;
                    if (colorIndex == colors.Length) colorIndex = 0;
                }

                var msg =
                    Right(f.Offset.ToString("X"), 8) + ' ' +
                    Left(f.Group, 20) +
                    Left(f.Type.ToString(), 6) +
                    Left(f.Name, 35) +
                    Right(f.ULongValue.ToString("X"), 9) +
                    (' ' + f.Comment ?? "");

                PrintColoredLine(msg, colors[colorIndex]);
            }
        }

        static void PrintColoredLine(string msg, string color)
        {
            msg = IsOutputRedirected ? msg : msg.Pastel(color);
            Console.WriteLine(msg);
        }

        static string Right(string s, int len)
        {
            return s.PadLeft(len).Substring(0, len);
        }

        static string Left(string s, int len)
        {
            return s.PadRight(len).Substring(0, len);
        }

        private static bool IsOutputRedirected = Console.IsOutputRedirected;
    }
}
