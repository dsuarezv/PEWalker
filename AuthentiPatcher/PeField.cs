﻿using System;
using System.Collections.Generic;
using System.Text;

namespace AuthentiPatcher
{
    public class PeField
    {
        public FieldType Type;
        public long Offset;
        public uint Size;
        public string Name;
        public string Group;
        public string Comment;

        public ulong ULongValue;
        public byte[] ByteValue;
    }



    public enum FieldType
    { 
        WORD = 1, 
        DWORD = 2, 
        QWORD = 3,
        BYTES = 4, 

    }
}
