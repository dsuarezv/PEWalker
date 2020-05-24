using Pastel;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthentiPatcher
{
    class PrintCommand
    {
        public void Process(string[] args)
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
