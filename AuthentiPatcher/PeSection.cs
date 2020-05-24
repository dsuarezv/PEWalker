using System;
using System.Collections.Generic;
using System.Text;

namespace AuthentiPatcher
{
    public class PeSection
    {
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint RawDataSize;
        public uint RawDataPointer;
        public uint RelocationPointer;
        public uint LineNumbersPointer;
        public int NumRelocations;
        public int NumLineNumbers;
        public uint Characteristics;
    }
}
