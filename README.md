## CDEL-Edu 正保远程教育 (China Distance Education Holdings Ltd.) Decrypter

This is a pure C# implementation of the proprietary key encryption done by CdelEdu. \
The WebAssembly firstly modifies the raw key a bit, base64 decodes it and then decrypts it using the custom cipher. \
\
The resulting key can be used to decrypt the video file using AES-CBC. \
**The IV is the fragment number of each segment starting at 1 converted to bytes in big endian format.**

## Usage
```
CdelEdu Key Decrypter by github.com/DevLARLEY
Usage: CdelEduDecrypt.exe [key]
```

## Build
```shell
dotnet publish
```