using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace AuthentiPatcher
{
    class OffsetUtils
    {
        public static (long, uint) ParseOffset(PeParser parser, string offset)
        {
            var result = ParseNumber(offset);
            if (result != -1) return (result, 0);

            // Try section names
            var section = parser.FindSection(offset);
            if (section != null) return (section.RawDataPointer, section.RawDataSize);

            throw new Exception($"Invalid offset '{offset}'");

            // TODO: Try group.name combination
        }


        public static long ParseNumber(string number)
        {
            if (number.StartsWith("0x") || number.EndsWith("h"))
            {
                // Hex
                if (long.TryParse(number, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long result))
                {
                    return result;
                }
            }
            else
            {
                if (long.TryParse(number, out long result)) return result;
            }

            return -1;
        }
    }
}
