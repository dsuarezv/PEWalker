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
