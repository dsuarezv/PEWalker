using System;
using System.Collections.Generic;
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
                P.Info("  authentipatch dump sx c:\\windows\\system32\\calc.exe .text");
                P.Info("  authentipatch dump hex c:\\windows\\system32\\calc.exe .text");
                P.Info("  authentipatch dump raw c:\\windows\\system32\\calc.exe 307200 0x345");
                return;
            }

            P.Error("Not implemented");
        }
    }
}
