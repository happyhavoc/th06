# 東方紅魔郷　～ the Embodiment of Scarlet Devil

[![Discord][discord-badge]][discord]

[discord]: https://discord.gg/VyGwAjrh9a
[discord-badge]: https://img.shields.io/discord/1147558514840064030?color=%237289DA&logo=discord&logoColor=%23FFFFFF

This project aims to perfectly reconstruct the source code of [Touhou Koumakyou ~ the Embodiment of Scarlet Devil 1.02h](https://en.touhouwiki.net/wiki/Embodiment_of_Scarlet_Devil) by Team Shanghai Alice.

**This project is still highly work in progress and in its early stages.**


## Installation

### Executable

This project requires the original `東方紅魔郷.exe` version 1.02h (9f76483c46256804792399296619c1274363c31cd8f1775fafb55106fb852245)

Copy `東方紅魔郷.exe` to `resources/game.exe`.

### Linux/macOS

#### Dependencies

The build system has the following package requirements:
- `python3` >= 3.9
- `curl`
- `msiextract`
- `p7zip` (or 7-Zip on Windows)
- `wine` (prefer CrossOver on macOS to avoid possible CL.EXE heap issues)

The rest of the build system is constructed out of Visual Studio 2002 and DirectX 8.0 from the Web Archive.


### Windows

Run the following commands in PowerShell:
```ps1
.\scripts\download_requirements.ps1
py -3 .\scripts\create_devenv.py .\scripts\dls\ .\scripts\prefix
```

#### Configure devenv

Run the following script:
```bash
# NOTE: On macOS if you use CrossOver.
# export WINE=<CrossOverPath>/wine
./scripts/create_th06_prefix
```

### Building

On Windows, run `scripts/build.bat` otherwise `./scripts/wineth06 scripts/build.bat`.
