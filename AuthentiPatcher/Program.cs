using System;

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
                    case "print": new PrintCommand().Process(args); break;
                    case "dump": new DumpCommand().Process(args); break;
                    case "patch": new PatchCommand().Process(args); break;
                    case "addauthpayload": new AddPayloadCommand().Process(args); break;
                    default: throw new Exception($"Unknown command {command}");
                }
            }
            catch (Exception ex)
            { 
                P.Error(ex.Message);
            }
        }
    }
}
