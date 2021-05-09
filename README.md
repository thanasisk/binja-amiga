# binja-amiga
A binary ninja plugin for Amiga 500 executables
## Prerequisites
A Motorola 68K series Binary Ninja plugin such as https://github.com/wrigjl/binaryninja-m68k
## Installation
`git clone git@github.com:thanasisk/binja-amiga.git $PLUGINDIR/amiga`
## I am sold! How can I immediately test it? I don't have access to an Amiga
There are some sample binaries included in this repo. `hello-debug` has debug symbols
## Cool bits
Supports A500/OCS special registers - they are automatically added as symbols.
## Limitations/Known bugs
- Currently Copper support is WiP, it is only interactive
- Not extensively tested, consider this alpha for now
- Base address is currently hardcoded
- Libraries support is currrently not implemented
## Licence
MIT
## Thanks
- The Binary Ninja slack crew for their magnificent support
- crabfists from English Amiga Board for inspiration
- KaiN and the AmigaDev Discord community
- The Amiga engineering team for creating a computer worth examining decades after its release
