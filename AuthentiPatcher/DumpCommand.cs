using System;
using System.Text;

namespace AuthentiPatcher
{
    class DumpCommand
    {
        public void Process(string[] args)
        {
            if (args.Length < 4)
            {
                P.Info("dump command usage");
                P.Info("  authentipatch dump <format> <filename> <offset> [size]");
                P.Info("    format can be any of:");
                //P.Info("      raw  raw bytes printed to the output. Recomended redirection.");
                P.Info("      hex  00 4F 3B AB 00 44 01 0A  00 4F 3B AB 00 44 01 0A");
                P.Info("      sx   \\x00\\x4F\\x3B\\xAB\\x00\\x44\\x01\\x0A\\x00\\x4F\\x3B\\xAB\\x00\\x44\\x01\\x0A");
                P.Info("      zx   0x00,0x4F,0x3B,0xAB,0x00,0x44,0x01,0x0A,0x00,0x4F,0x3B,0xAB,0x00,0x44,0x01,0x0A");
                P.Info("    offset can be any of:");
                P.Info("      section name: .text  In this case, size is not required");
                P.Info("      decimal value: 34563");
                P.Info("      hex value: 0x34A63");
                P.Info("");
                P.Info("Samples:");
                P.Info("  authentipatch dump sx c:\\windows\\system32\\calc.exe .text");
                P.Info("  authentipatch dump hex c:\\windows\\system32\\calc.exe .text");
                P.Info("  authentipatch dump raw c:\\windows\\system32\\calc.exe 307200 0x345");
                return;
            }

            var format = args[1];
            var inputFile = args[2];
            long offset, size;
            byte[] content;
            Action<byte[]> formatter;

            switch (format.ToLower())
            {
                //case "raw": formatter = DumpRawContent; break;
                case "hex": formatter = DumpHexContent; break;
                case "sx": formatter = DumpSXContent; break;
                case "zx": formatter = DumpZXContent; break;
                default: throw new Exception($"Invalid format '{format}'");

            }

            using (var parser = new PeParser(inputFile))
            {
                parser.Parse();

                (offset, size) = OffsetUtils.ParseOffset(parser, args[3]);

                if (args.Length > 4) size = OffsetUtils.ParseNumber(args[4]);
                if (size == 0 || size == -1) throw new Exception("Must specify a size");

                // load the target content
                parser.SeekAbsolute(offset);
                content = parser.Reader.ReadBytes((int)size);
            }

            formatter(content);
        }

        static void DumpRawContent(byte[] content)
        {

        }

        static void DumpHexContent(byte[] content)
        {
            var lineBuffer = new byte[16];

            for (int i = 0; i < content.Length; ++i)
            {
                if (i % 16 == 0) Console.Write(i.ToString("x8") + "  ");

                lineBuffer[i % 16] = content[i];

                Console.Write(content[i].ToString("X2") + ' ');

                if (i % 8 == 7) Console.Write(' ');
                if (i % 16 == 15)
                {
                    PrintAsciiLine(lineBuffer);
                    Console.WriteLine();
                }
            }
        }

        static void DumpSXContent(byte[] content)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < content.Length; ++i)
            {
                sb.Append("\\x" + content[i].ToString("X2"));
            }

            Console.WriteLine(sb.ToString());

        }

        static void DumpZXContent(byte[] content)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < content.Length; ++i)
            {
                sb.Append("0x" + content[i].ToString("X2"));

                if (i < content.Length - 1) sb.Append(',');
            }

            Console.WriteLine(sb.ToString());
        }



        static void PrintAsciiLine(byte[] line)
        {
            for (int i = 0; i < line.Length; ++i)
            {
                var c = line[i];
                Console.Write((c < 32 || c > 92) ? '.' : (char)c);
            }
        }
    }
}
