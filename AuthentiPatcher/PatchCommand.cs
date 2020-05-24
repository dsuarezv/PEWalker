using System;
using System.Collections.Generic;
using System.Text;

namespace AuthentiPatcher
{
    class PatchCommand
    {
        public void Process(string[] args)
        {
            if (args.Length != 4)
            {
                P.Info("patch command usage");
                P.Info("  authentipatch patch <inputfile> <offset> <content>");
                return;
            }

            P.Error("Not implemented");
        }
    }
}
