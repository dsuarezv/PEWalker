using Pastel;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthentiPatcher
{
    class P
    {
        public static void Error(string msg)
        {
            Console.WriteLine("[-] ".Pastel("FF0000") + msg);
        }

        public static void Info(string msg)
        {
            Console.WriteLine("[i] ".Pastel("FFFFFF") + msg);
        }

        public static void Success(string msg)
        {
            Console.WriteLine("[+] ".Pastel("00FF00") + msg);
        }

        public static void Banner()
        {
            Console.WriteLine(@"   _____          __  .__                   __  .__ ".Pastel("d16ba5"));
            Console.WriteLine(@"  /  _  \  __ ___/  |_|  |__   ____   _____/  |_|__|".Pastel("c777b9"));
            Console.WriteLine(@" /  /_\  \|  |  \   __\  |  \_/ __ \ /    \   __\  |".Pastel("ba83ca"));
            Console.WriteLine(@"/    |    \  |  /|  | |   Y  \  ___/|   |  \  | |  |".Pastel("aa8fd8"));
            Console.WriteLine(@"\____|__  /____/ |__| |___|  /\___  >___|  /__| |__|".Pastel("9a9ae1"));
            Console.WriteLine(@"________\/        __       \/.__  \/     \/         ".Pastel("81a1e5"));
            Console.WriteLine(@"\______   \____ _/  |_  ____ |  |__   ___________   ".Pastel("66a8e5"));
            Console.WriteLine(@" |     ___|__  \\   __\/ ___\|  |  \_/ __ \_  __ \  ".Pastel("4eade0"));
            Console.WriteLine(@" |    |    / __ \|  | \  \___|   Y  \  ___/|  | \/  ".Pastel("1dafd2"));
            Console.WriteLine(@" |____|   (____  /__|  \___  >___|  /\___  >__|     ".Pastel("00afbe"));
            Console.WriteLine(@"               \/          \/     \/     \/         ".Pastel("1dada5"));
            Console.WriteLine();
        }
    }
}
