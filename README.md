# binja-amiga
A binary ninja plugin for Amiga 500 executables
## Prerequisites
A Motorola 68K series Binary Ninja plugin such as https://github.com/wrigjl/binaryninja-m68k

The canonical way is to install the Motorola 68000 plugin via the plugin manager.
## Installation
`git clone git@github.com:thanasisk/binja-amiga.git $PLUGINDIR/binja-amiga`
## I am sold! How can I immediately test it? I don't have access to an Amiga
There are some sample binaries included in this repo. `hello-debug` has debug symbols
## Cool bits
Supports A500/OCS special registers - they are automatically added as symbols.
## Limitations/Known bugs
- Currently Copper support is WiP, it is only interactive
- Not extensively tested, bug reports welcome
- Libraries support is currrently WiP
## Licence
MIT
## Thanks
- The Binary Ninja slack crew for their magnificent support
- crabfists from English Amiga Board for inspiration
- KaiN and the AmigaDev Discord community
- The Amiga engineering team for creating a computer worth examining decades after its release
