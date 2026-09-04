# VMProtect Unpacker

VMProtect 3.x unpacker. Static LZMA unpack, runtime dump, IAT fix.

## usage

```text
VMProtect.exe <packed> <out>
VMProtect.exe --runtime [--wait ms] <packed> <out>
VMProtect.exe --pid <pid> [--module name] <out>
```

## examples

```text
VMProtect.exe packed.exe unpacked.exe
VMProtect.exe --runtime packed.exe dumped.exe
VMProtect.exe --pid 1234 --module Loader.exe(you can specify it to dump another injected module) dumped.exe
```
