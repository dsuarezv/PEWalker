﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text;

namespace AuthentiPatcher
{
    public class PeParser: IDisposable
    {
        public BinaryReader Reader { get; private set; }
        public List<PeField> Fields { get; } = new List<PeField>();
        public int NumberOfSections { get; private set; }

        public int CertificateStart;
        public int CertificateSize;

        public PeParser(string fileName)
        {
            Reader = new BinaryReader(File.OpenRead(fileName));
        }

        public PeParser(Stream inputStream)
        {
            Reader = new BinaryReader(inputStream);
        }

        public void Dispose()
        {
            if (Reader != null) Reader.Dispose();
        }


        public void Parse()
        {
            var peHeaderOffset = ParseDosHeader();

            SeekAbsolute(peHeaderOffset);

            var sizeOfOptionalHeader = ParseCoffHeader();
            if (sizeOfOptionalHeader > 0)
            {
                ParseOptionalHeader();
            }

            ParseSections();
            
            ParseCertificate();
        }

        public IEnumerable<PeField> Find(string group, string name)
        {
            return Fields.Where(f => {
                if (group != null && name != null)
                {
                    return f.Group.Contains(group) && f.Name.Contains(name);
                }
                else if (group != null)
                {
                    return f.Group.Contains(group);
                }
                else if (name != null)
                {
                    return f.Name.Contains(name);
                }

                return false;
            });
        }

        public ulong FindValue(string group, string name)
        {
            var result = Find(group, name).FirstOrDefault();
            if (result == null) return 0;

            return result.ULongValue;
        }

        private int ParseDosHeader()
        {
            ReadWORD("DOS", "Signature");
            ReadBytes("DOS", "BODY NOT Parsed", 0x3A);
            var result = ReadDWORD("DOS", "Pointer to PE Header");

            return result;
        }

        private int ParseCoffHeader()
        {
            ReadDWORD("COFF Header", "Signature");
            ReadWORD("COFF Header", "Machine");
            NumberOfSections = ReadWORD("COFF Header", "Number of sections");
            ReadDWORD("COFF Header", "TimeDateStamp");
            ReadDWORD("COFF Header", "Pointer to Symbol Table");
            ReadDWORD("COFF Header", "Number of Symbols (deprecated)");
            var result = ReadWORD("COFF Header", "Size of optional Header");
            ReadWORD("COFF Header", "Characteristics");

            return result;
        }

        private void ParseOptionalHeader()
        {
            var magic = ReadWORD("COFF common fields", "Signature", v => { v.Comment = v.ULongValue == 0x10b ? "PE32" : "PE32+"; });
            
            ReadWORD("COFF common fields", "Linker version");
            ReadDWORD("COFF common fields", "Size of code (sum of all sections)");
            ReadDWORD("COFF common fields", "Size of initialized data");
            ReadDWORD("COFF common fields", "Size of uninitialized data");
            ReadDWORD("COFF common fields", "Address of entry point (RVA)");
            ReadDWORD("COFF common fields", "Base of code (RVA)");

            int numRvas;

            if (magic == 0x10b)
            {
                // PE32
                ReadDWORD("COFF common fields", "Base of data (RVA)");
                ReadDWORD("Windows fields", "ImageBase");
                ReadDWORD("Windows fields", "Section alignment");
                ReadDWORD("Windows fields", "File alignment");
                ReadWORD("Windows fields", "Major operating system version");
                ReadWORD("Windows fields", "Minor operating system version");
                ReadWORD("Windows fields", "Major image version");
                ReadWORD("Windows fields", "Minor image version");
                ReadWORD("Windows fields", "Major subsystem version");
                ReadWORD("Windows fields", "Minor subsystem version");
                ReadDWORD("Windows fields", "Win32 version value");
                

                ReadDWORD("Windows fields", "Size of image");
                ReadDWORD("Windows fields", "Size of headers");
                ReadDWORD("Windows fields", "Checksum (images not checked)");
                ReadWORD("Windows fields", "Subsystem");
                ReadWORD("Windows fields", "Dll characteristics");
                ReadDWORD("Windows fields", "Size of Stack Reserve");
                ReadDWORD("Windows fields", "Size of Stack Commit");
                ReadDWORD("Windows fields", "Size of Heap Reserve");
                ReadDWORD("Windows fields", "Size of Heap Commit");
                ReadDWORD("Windows fields", "Loader flags");
                numRvas = ReadDWORD("Windows fields", "Number of RVA and sizes");
            }
            else
            {
                // PE32+
                ReadQWORD("Windows fields", "ImageBase");
                ReadDWORD("Windows fields", "Section alignment");
                ReadDWORD("Windows fields", "File alignment");
                ReadWORD("Windows fields", "Major operating system version");
                ReadWORD("Windows fields", "Minor operating system version");
                ReadWORD("Windows fields", "Major image version");
                ReadWORD("Windows fields", "Minor image version");
                ReadWORD("Windows fields", "Major subsystem version");
                ReadWORD("Windows fields", "Minor subsystem version");
                ReadDWORD("Windows fields", "Win32 version value");

                ReadDWORD("Windows fields", "Size of image");
                ReadDWORD("Windows fields", "Size of headers");
                ReadDWORD("Windows fields", "Checksum (images not checked)");
                ReadWORD("Windows fields", "Subsystem");
                ReadWORD("Windows fields", "Dll characteristics");
                ReadQWORD("Windows fields", "Size of Stack Reserve");
                ReadQWORD("Windows fields", "Size of Stack Commit");
                ReadQWORD("Windows fields", "Size of Heap Reserve");
                ReadQWORD("Windows fields", "Size of Heap Commit");
                ReadDWORD("Windows fields", "Loader flags");
                numRvas = ReadDWORD("Windows fields", "Number of RVA and sizes");
            }

            if (numRvas >= 16)
            {
                ReadDataDirectory("Export table");
                ReadDataDirectory("Import table");
                ReadDataDirectory("Resource table");
                ReadDataDirectory("Exception table");
                ReadDataDirectory("Certificate table", (start, size) => { CertificateStart = start; CertificateSize = size; });
                ReadDataDirectory("Base relocation table");
                ReadDataDirectory("Debug");
                ReadDataDirectory("Architecture data");
                ReadDataDirectory("GlobalPtr (0)");
                ReadDataDirectory("TLS table");
                ReadDataDirectory("Load config table");
                ReadDataDirectory("Bound import");
                ReadDataDirectory("Import address table");
                ReadDataDirectory("Delay import descriptor");
                ReadDataDirectory("COM / CLR runtime header");
                ReadDataDirectory("??");
            }
            else
            { 
                // Just read the RVA size
            }
        }

        private void ReadDataDirectory(string name, Action<int, int> callback = null)
        {
            var start = ReadDWORD("Data directories", name);
            var size = ReadDWORD("Data directories", "Size of " + name);

            if (callback != null) callback.Invoke(start, size);
        }


        private void ParseSections()
        {
            for (int i = 0; i < NumberOfSections; ++i)
            {
                ParseSection();
            }
        }

        private void ParseSection()
        {
            string group = "";

            ReadBytes("", "Name", 8, v => { var g = Encoding.UTF8.GetString(v.ByteValue);  group = "Section " + g; v.Group = group; v.Comment = g; });
            ReadDWORD(group, "Virtual size");
            ReadDWORD(group, "Virtual address");
            ReadDWORD(group, "Size of raw data");
            ReadDWORD(group, "Pointer to raw data");
            ReadDWORD(group, "Pointer to relocations");
            ReadDWORD(group, "Pointer to line numbers");
            ReadWORD(group, "Number of relocations");
            ReadWORD(group, "Number of line elements");
            ReadDWORD(group, "Characteristics");
        }

        private void ParseCertificate()
        {
            if (CertificateStart == 0 || CertificateSize == 0) return;

            SeekAbsolute(CertificateStart);

            var len = ReadDWORD("WIN_CERTIFICATE", "Length");
            ReadWORD("WIN_CERTIFICATE", "Revision", f => f.Comment = GetCertRevision((ushort)f.ULongValue));
            ReadWORD("WIN_CERTIFICATE", "Certificate type", f => f.Comment = GetCertType((ushort)f.ULongValue));
            ReadBytes("WIN_CERTIFICATE", "Certificates", len - 8);
        }

        // __ Reading utils ___________________________________________________

        private void SeekAbsolute(int offset)
        {
            Reader.BaseStream.Seek(offset, SeekOrigin.Begin);
        }

        private void SeekRelative(int offsetFromCurrent)
        {
            Reader.BaseStream.Seek(offsetFromCurrent, SeekOrigin.Current);
        }

        private int ReadDWORD(string group, string name, Action<PeField> callback = null)
        {
            var entry = new PeField
            {
                Type = FieldType.DWORD,
                Group = group,
                Name = name,
                Size = 4,
                Offset = (int)Reader.BaseStream.Position,
                ULongValue = Reader.ReadUInt32()
            };

            Fields.Add(entry);

            if (callback != null) callback.Invoke(entry);

            return (int)entry.ULongValue;
        }

        private int ReadWORD(string group, string name, Action<PeField> callback = null)
        {
            var entry = new PeField
            {
                Type = FieldType.WORD,
                Group = group,
                Name = name,
                Size = 2,
                Offset = (int)Reader.BaseStream.Position,
                ULongValue = Reader.ReadUInt16()
            };

            Fields.Add(entry);

            if (callback != null) callback.Invoke(entry);

            return (int)entry.ULongValue;
        }

        private UInt64 ReadQWORD(string group, string name)
        {
            var entry = new PeField
            {
                Type = FieldType.QWORD,
                Group = group,
                Name = name,
                Size = 8,
                Offset = (int)Reader.BaseStream.Position,
                ULongValue = Reader.ReadUInt64()
            };

            Fields.Add(entry);

            return entry.ULongValue;
        }

        private PeField ReadBytes(string group, string name, int numBytes, Action<PeField> callback = null)
        {
            var entry = new PeField
            {
                Type = FieldType.BYTES,
                Group = group,
                Name = name,
                Size = numBytes,
                Offset = (int)Reader.BaseStream.Position,
                ByteValue = Reader.ReadBytes(numBytes)
            };

            Fields.Add(entry);

            if (callback != null) callback.Invoke(entry);

            return entry;
        }


        // __ Type helpers ____________________________________________________


        static string GetCertRevision(UInt16 rev)
        {
            switch (rev)
            {
                case 0x0100: return "WIN_CERT_REVISION_1_0";
                case 0x0200: return "WIN_CERT_REVISION_2_0";
                default: return "REVISION_UNKNOWN";
            }
        }

        static string GetCertType(UInt16 type)
        {
            switch (type)
            {
                case 0x0001: return "WIN_CERT_TYPE_X509";
                case 0x0002: return "WIN_CERT_TYPE_PKCS_SIGNED_DATA";
                case 0x0003: return "WIN_CERT_TYPE_RESERVED_1";
                case 0x0004: return "WIN_CERT_TYPE_STACK_SIGNED";
                case 0x0EF0: return "WIN_CERT_EFI_PKCS115";
                case 0x0EF1: return "WIN_CERT_TYPE_EFI_GUID";
                default: return "TYPE_UNKNOWN";
            }
        }
    }
}
