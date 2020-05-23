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
            Console.WriteLine(Color("[-] ", "FF0000") + msg);
        }

        public static void Info(string msg)
        {
            Console.WriteLine(Color("[i] ", "FFFFFF") + msg);
        }

        public static void Warn(string msg)
        {
            Console.WriteLine(Color("[!] ", "FFDE00") + msg);
        }

        public static void Success(string msg)
        {
            Console.WriteLine(Color("[+] ", "00FF00") + msg);
        }

        public static void Banner()
        {
            Console.WriteLine(Color(@"   _____          __  .__                   __  .__ ", "d16ba5"));
            Console.WriteLine(Color(@"  /  _  \  __ ___/  |_|  |__   ____   _____/  |_|__|", "c777b9"));
            Console.WriteLine(Color(@" /  /_\  \|  |  \   __\  |  \_/ __ \ /    \   __\  |", "ba83ca"));
            Console.WriteLine(Color(@"/    |    \  |  /|  | |   Y  \  ___/|   |  \  | |  |", "aa8fd8"));
            Console.WriteLine(Color(@"\____|__  /____/ |__| |___|  /\___  >___|  /__| |__|", "9a9ae1"));
            Console.WriteLine(Color(@"________\/        __       \/.__  \/     \/         ", "81a1e5"));
            Console.WriteLine(Color(@"\______   \____ _/  |_  ____ |  |__   ___________   ", "66a8e5"));
            Console.WriteLine(Color(@" |     ___|__  \\   __\/ ___\|  |  \_/ __ \_  __ \  ", "4eade0"));
            Console.WriteLine(Color(@" |    |    / __ \|  | \  \___|   Y  \  ___/|  | \/  ", "1dafd2"));
            Console.WriteLine(Color(@" |____|   (____  /__|  \___  >___|  /\___  >__|     ", "00afbe"));
            Console.WriteLine(Color(@"               \/          \/     \/     \/         ", "1dada5"));
            Console.WriteLine();
        }

        private static string Color(string msg, string color)
        {
            msg = IsOutputRedirected ? msg : msg.Pastel(color);
            return msg;
        }

        private static bool IsOutputRedirected = Console.IsOutputRedirected;
    }
}
