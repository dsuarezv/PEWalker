# PE walker

This is just a toy project I made while attending the course II Experto Universitario en Ingeniería Inversa e Inteligencia Malware at Universidad de Málaga. 

This code contains a parser of the PE (Portable Executable) structure. By default it prints the details of the different sections, in various colors. Here is a screenshot: 

![](screenshots/01.png)

The PE format is the executable format used in Windows, for both EXE and DLL files. [It is well documented in MSDN](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).  

This project is not meant as a full command line utility, it's more a collection of code fragments that can be used from other code to perform specific actions on executable files. I will eventually make it a library. Who knows, maybe a proper Windows GUI. Will depend on how the course evolves.

The original goal was to patch an exe file signed with authenticode and still keep the signature valid, thus the name AuthentiPatcher. There are certain places in the PE format that are not validated by the signature and they can be used to hide payloads.

## Usage

Out of the box, the program can dump the contents of the PE headers. Invoke it with the exe file you want to analyze:

    authentipatcher c:\windows\system32\calc.exe

This will print all the fields it knows about in the console: 

![](screenshots/sections.png)

### Patching files

It can also append a payload at the end of the certificates area, if invoked with some more arguments. The signature of the file will still be valid after this. 

    authentipatcher <inputfile> <payloadfile> <outputfile>

There are some requirements for this to work: 

* The payload size must be a mutiple of 8. This is required by the PE format. 
* The target executable should not have debug symbols. This is not normal in signed files, but if there are, they will be overwritten and the signature validation will fail in that case. 

## Building

The code is written in C# for dotnet core 3.1, but will probably work in previous versions (I haven't tested). Install the dotnetcore SDK in your platform and you are ready to roll. 

For console colors, it uses the great C# [Pastel library](https://github.com/silkfire/Pastel).

## API

The interesting part is the PeParser class. Provided with a file, it will parse the PE header and the different fields can be enumerated or filtered:

        using (var parser = new PeParser(inputFile))
        {
            parser.Parse();

            var certSize = parser.Find(null, "Size of Certificate table").FirstOrDefault();
            Console.WriteLine($"Size: {certSize.ULongValue}");
            Console.WriteLine($"Offset {certSize.Offset}");
        }

## Sample output

Here is a list of the full report generated for now by the tool: 

  [i] File: c:\Windows\System32\calc.exe
  
    OFFSET GROUP               TYPE  NAME                               VALUE(hex COMMENT
         0 DOS                 WORD  Signature                               5A4D 
         2 DOS                 BYTES BODY NOT Parsed                            0 
        3C DOS                 DWORD Pointer to PE Header                      F8 
        F8 COFF Header         DWORD Signature                               4550 
        FC COFF Header         WORD  Machine                                 8664 
        FE COFF Header         WORD  Number of sections                         6 
       100 COFF Header         DWORD TimeDateStamp                       C2B75AE3 
       104 COFF Header         DWORD Pointer to Symbol Table                    0 
       108 COFF Header         DWORD Number of Symbols (deprecated)             0 
       10C COFF Header         WORD  Size of optional Header                   F0 
       10E COFF Header         WORD  Characteristics                           22 
       110 COFF common fields  WORD  Signature                                20B PE32+
       112 COFF common fields  WORD  Linker version                           F0E 
       114 COFF common fields  DWORD Size of code (sum of all sections)       C00 
       118 COFF common fields  DWORD Size of initialized data                6200 
       11C COFF common fields  DWORD Size of uninitialized data                 0 
       120 COFF common fields  DWORD Address of entry point (RVA)            1820 
       124 COFF common fields  DWORD Base of code (RVA)                      1000 
       128 Windows fields      QWORD ImageBase                          140000000 
       130 Windows fields      DWORD Section alignment                       1000 
       134 Windows fields      DWORD File alignment                           200 
       138 Windows fields      WORD  Major operating system version             A 
       13A Windows fields      WORD  Minor operating system version             0 
       13C Windows fields      WORD  Major image version                        A 
       13E Windows fields      WORD  Minor image version                        0 
       140 Windows fields      WORD  Major subsystem version                    A 
       142 Windows fields      WORD  Minor subsystem version                    0 
       144 Windows fields      DWORD Win32 version value                        0 
       148 Windows fields      DWORD Size of image                           B000 
       14C Windows fields      DWORD Size of headers                          400 
       150 Windows fields      DWORD Checksum (images not checked)           CC9C 
       154 Windows fields      WORD  Subsystem                                  2 
       156 Windows fields      WORD  Dll characteristics                     C160 
       158 Windows fields      QWORD Size of Stack Reserve                  80000 
       160 Windows fields      QWORD Size of Stack Commit                    2000 
       168 Windows fields      QWORD Size of Heap Reserve                  100000 
       170 Windows fields      QWORD Size of Heap Commit                     1000 
       178 Windows fields      DWORD Loader flags                               0 
       17C Windows fields      DWORD Number of RVA and sizes                   10 
       180 Data directories    DWORD Export table                               0 
       184 Data directories    DWORD Size of Export table                       0 
       188 Data directories    DWORD Import table                            2784 
       18C Data directories    DWORD Size of Import table                      A0 
       190 Data directories    DWORD Resource table                          5000 
       194 Data directories    DWORD Size of Resource table                  4710 
       198 Data directories    DWORD Exception table                         4000 
       19C Data directories    DWORD Size of Exception table                   E4 
       1A0 Data directories    DWORD Certificate table                          0 
       1A4 Data directories    DWORD Size of Certificate table                  0 
       1A8 Data directories    DWORD Base relocation table                   A000 
       1AC Data directories    DWORD Size of Base relocation table             2C 
       1B0 Data directories    DWORD Debug                                   2310 
       1B4 Data directories    DWORD Size of Debug                             54 
       1B8 Data directories    DWORD Architecture data                          0 
       1BC Data directories    DWORD Size of Architecture data                  0 
       1C0 Data directories    DWORD GlobalPtr (0)                              0 
       1C4 Data directories    DWORD Size of GlobalPtr (0)                      0 
       1C8 Data directories    DWORD TLS table                                  0 
       1CC Data directories    DWORD Size of TLS table                          0 
       1D0 Data directories    DWORD Load config table                       2010 
       1D4 Data directories    DWORD Size of Load config table                108 
       1D8 Data directories    DWORD Bound import                               0 
       1DC Data directories    DWORD Size of Bound import                       0 
       1E0 Data directories    DWORD Import address table                    2118 
       1E4 Data directories    DWORD Size of Import address table             140 
       1E8 Data directories    DWORD Delay import descriptor                    0 
       1EC Data directories    DWORD Size of Delay import descriptor            0 
       1F0 Data directories    DWORD COM / CLR runtime header                   0 
       1F4 Data directories    DWORD Size of COM / CLR runtime header           0 
       1F8 Data directories    DWORD ??                                         0 
       1FC Data directories    DWORD Size of ??                                 0 
       200 Section .text       BYTES Name                                       0 .text   
       208 Section .text       DWORD Virtual size                             B80 
       20C Section .text       DWORD Virtual address                         1000 
       210 Section .text       DWORD Size of raw data                         C00 
       214 Section .text       DWORD Pointer to raw data                      400 
       218 Section .text       DWORD Pointer to relocations                     0 
       21C Section .text       DWORD Pointer to line numbers                    0 
       220 Section .text       WORD  Number of relocations                      0 
       222 Section .text       WORD  Number of line elements                    0 
       224 Section .text       DWORD Characteristics                     60000020 
       228 Section .rdata      BYTES Name                                       0 .rdata  
       230 Section .rdata      DWORD Virtual size                             C66 
       234 Section .rdata      DWORD Virtual address                         2000 
       238 Section .rdata      DWORD Size of raw data                         E00 
       23C Section .rdata      DWORD Pointer to raw data                     1000 
       240 Section .rdata      DWORD Pointer to relocations                     0 
       244 Section .rdata      DWORD Pointer to line numbers                    0 
       248 Section .rdata      WORD  Number of relocations                      0 
       24A Section .rdata      WORD  Number of line elements                    0 
       24C Section .rdata      DWORD Characteristics                     40000040 
       250 Section .data       BYTES Name                                       0 .data   
       258 Section .data       DWORD Virtual size                             638 
       25C Section .data       DWORD Virtual address                         3000 
       260 Section .data       DWORD Size of raw data                         200 
       264 Section .data       DWORD Pointer to raw data                     1E00 
       268 Section .data       DWORD Pointer to relocations                     0 
       26C Section .data       DWORD Pointer to line numbers                    0 
       270 Section .data       WORD  Number of relocations                      0 
       272 Section .data       WORD  Number of line elements                    0 
       274 Section .data       DWORD Characteristics                     C0000040 
       278 Section .pdata      BYTES Name                                       0 .pdata  
       280 Section .pdata      DWORD Virtual size                              E4 
       284 Section .pdata      DWORD Virtual address                         4000 
       288 Section .pdata      DWORD Size of raw data                         200 
       28C Section .pdata      DWORD Pointer to raw data                     2000 
       290 Section .pdata      DWORD Pointer to relocations                     0 
       294 Section .pdata      DWORD Pointer to line numbers                    0 
       298 Section .pdata      WORD  Number of relocations                      0 
       29A Section .pdata      WORD  Number of line elements                    0 
       29C Section .pdata      DWORD Characteristics                     40000040 
       2A0 Section .rsrc       BYTES Name                                       0 .rsrc   
       2A8 Section .rsrc       DWORD Virtual size                            4710 
       2AC Section .rsrc       DWORD Virtual address                         5000 
       2B0 Section .rsrc       DWORD Size of raw data                        4800 
       2B4 Section .rsrc       DWORD Pointer to raw data                     2200 
       2B8 Section .rsrc       DWORD Pointer to relocations                     0 
       2BC Section .rsrc       DWORD Pointer to line numbers                    0 
       2C0 Section .rsrc       WORD  Number of relocations                      0 
       2C2 Section .rsrc       WORD  Number of line elements                    0 
       2C4 Section .rsrc       DWORD Characteristics                     40000040 
       2C8 Section .reloc      BYTES Name                                       0 .reloc  
       2D0 Section .reloc      DWORD Virtual size                              2C 
       2D4 Section .reloc      DWORD Virtual address                         A000 
       2D8 Section .reloc      DWORD Size of raw data                         200 
       2DC Section .reloc      DWORD Pointer to raw data                     6A00 
       2E0 Section .reloc      DWORD Pointer to relocations                     0 
       2E4 Section .reloc      DWORD Pointer to line numbers                    0 
       2E8 Section .reloc      WORD  Number of relocations                      0 
       2EA Section .reloc      WORD  Number of line elements                    0 
       2EC Section .reloc      DWORD Characteristics                     42000040 
