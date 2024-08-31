from enum import Enum
import json
from pathlib import Path

from ninja_syntax import Writer

SCRIPTS_DIR = Path(__file__).parent


class BuildType(Enum):
    NORMAL = 1
    DIFFBUILD = 2
    TESTS = 3
    DLLBUILD = 4
    OBJDIFFBUILD = 5


def configure(build_type):
    with (SCRIPTS_DIR.parent / "build.ninja").open("w") as f:
        writer = Writer(f, width=120)
        writer.variable("ninja_required_version", "1.5")

        writer.variable("builddir", "build")

        writer.variable("cl", "cl.exe")
        writer.variable(
            "cl_common_flags",
            "/MT /EHsc /G5 /Gs /GS /DNDEBUG /Zi /I $builddir/autogenerated /I src /I 3rdparty/munit /I 3rdparty/Detours/src",
        )
        writer.variable("cl_flags", "$cl_common_flags /Od /Oi /Ob1 /Op")
        writer.variable("cl_flags_pbg3", "$cl_common_flags /O2")
        writer.variable(
            "cl_flags_detours",
            "/W4 /WX /we4777 /we4800 /Zi /MT /Gy /Gm- /Zl /Od /DDETOUR_DEBUG=0 /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x501",
        )
        if build_type in [BuildType.DIFFBUILD, BuildType.DLLBUILD]:
            writer.variable("cl_flags", "$cl_flags /DDIFFBUILD")
            writer.variable("cl_flags_pbg3", "$cl_flags_pbg3 /DDIFFBUILD")
        writer.variable("rc", "rc.exe")
        writer.variable("link", "link.exe")
        writer.variable(
            "th06_link_flags",
            "/subsystem:windows /machine:X86 /filealign:4096 /incremental:no",
        )

        writer.variable("msvc_deps_prefix", "Note: including file:")
        writer.rule(
            "cc",
            "$cl /nologo /showIncludes $cl_flags /c $in /Fd$out.pdb /Fo$out",
            deps="msvc",
        )
        writer.rule(
            "cc_pbg3",
            "$cl /nologo /showIncludes $cl_flags_pbg3 /c $in /Fd$out.pdb /Fo$out",
            deps="msvc",
        )
        writer.rule(
            "cc_detours",
            "$cl /nologo /showIncludes $cl_flags_detours /Fd$out.pdb /Fo$out /c $in",
            deps="msvc",
        )
        writer.rule("genglobals", "python scripts/generate_globals.py $in $out")
        writer.rule("rc", "$rc /fo $out $in")
        writer.rule(
            "link",
            "$link $link_flags /nologo /out:$out $link_libs $in",
        )
        writer.rule(
            "copyicon",
            'python -c "import shutil; import sys; shutil.copyfile(sys.argv[1], sys.argv[2])" $in $out',
        )
        writer.rule(
            "geni18n",
            """python -c "import sys; open(sys.argv[2], 'wb').write(open(sys.argv[1], 'rb').read().decode('utf8').encode('shift_jis'))" $in $out""",
        )
        writer.rule(
            "genstubs",
            "python scripts/generate_stubs.py --output $out",
        )
        writer.rule(
            "gendetours",
            "python scripts/generate_detours.py --input-def $builddir/th06.def --output $out",
        )
        writer.rule(
            "gendef",
            "python scripts/gendef.py --output $out $in",
        )
        writer.rule(
            "rename_symbols",
            "python scripts/generate_objdiff_objs.py $in",
        )

        main_sources = ["main"]
        cxx_sources = [
            "AsciiManager",
            "BulletData",
            "BulletManager",
            "Chain",
            "EclManager",
            "EnemyManager",
            "Enemy",
            "FileSystem",
            "Supervisor",
            "GameErrorContext",
            "TextHelper",
            "GameWindow",
            "MainMenu",
            "ItemManager",
            "MidiOutput",
            "EffectManager",
            "ScreenEffect",
            "SoundPlayer",
            "Player",
            "Stage",
            "AnmVm",
            "AnmManager",
            "GameManager",
            "Gui",
            "Rng",
            "utils",
            "ZunTimer",
            "zwave",
        ]

        pbg3_sources = [
            "IPbg3Parser",
            "Pbg3Parser",
            "Pbg3Archive",
            "FileAbstraction",
        ]

        munit_sources = ["munit"]

        test_sources = [
            "tests",
            "test_Pbg3Archive",
        ]

        detours_sources = [
            "detours",
            "modules",
            "disasm",
            "image",
            "creatwth",
            "disolx86",
            "disolx64",
            "disolia64",
            "disolarm",
            "disolarm64",
        ]

        # TODO: might make more sense to work the other way around: generate
        # objdiff.json from the ninja.
        with open("objdiff.json") as f:
            objdiff_json = json.load(f)
        objdiff_deps = []
        for obj in objdiff_json["objects"]:
            objdiff_deps.append(obj["base_path"].replace("build", "$builddir"))
        writer.build("objdiff", "phony", [], objdiff_deps)

        for rule in main_sources + cxx_sources:
            writer.build(
                "$builddir/" + rule + ".obj",
                "cc",
                "src/" + rule + ".cpp",
                implicit=["$builddir/autogenerated/i18n.hpp"],
            )
            writer.build(
                "$builddir/objdiff/reimpl/" + rule + ".obj",
                "rename_symbols",
                "$builddir/" + rule + ".obj",
                implicit=["scripts/generate_objdiff_objs.py"],
            )

        for rule in pbg3_sources:
            writer.build(
                "$builddir/" + rule + ".obj",
                "cc_pbg3",
                "src/pbg3/" + rule + ".cpp",
                implicit=["$builddir/autogenerated/i18n.hpp"],
            )
            writer.build(
                "$builddir/objdiff/reimpl/" + rule + ".obj",
                "rename_symbols",
                "$builddir/" + rule + ".obj",
                implicit=["scripts/generate_objdiff_objs.py"],
            )

        for rule in munit_sources:
            writer.build(
                "$builddir/" + rule + ".obj",
                "cc",
                "3rdparty/munit/" + rule + ".c",
            )

        for rule in test_sources:
            writer.build(
                "$builddir/" + rule + ".obj",
                "cc",
                "tests/" + rule + ".cpp",
            )

        for rule in detours_sources:
            writer.build(
                "$builddir/" + rule + ".obj",
                "cc_detours",
                "3rdparty/Detours/src/" + rule + ".cpp",
            )

        writer.build(
            "$builddir/autogenerated/auto_stubbed.cpp",
            "genstubs",
            implicit=[
                "config/stubbed.csv",
                "config/mapping.csv",
                "scripts/generate_stubs.py",
            ],
        )
        writer.build(
            "$builddir/stubs.obj",
            "cc",
            "src/stubs.cpp",
            implicit=[
                "$builddir/autogenerated/auto_stubbed.cpp",
                "$builddir/autogenerated/i18n.hpp",
            ],
        )
        writer.build(
            "$builddir/autogenerated/detouring.cpp",
            "gendetours",
            implicit=[
                "config/implemented.csv",
                "config/mapping.csv",
                "scripts/generate_detours.py",
                "$builddir/th06.def",
            ],
        )
        writer.build(
            "$builddir/dllbuild.obj",
            "cc",
            "src/dllbuild.cpp",
            implicit=[
                "$builddir/autogenerated/detouring.cpp",
                "$builddir/autogenerated/i18n.hpp",
            ],
        )

        writer.build(
            "$builddir/globals.obj",
            "genglobals",
            inputs="config/globals.csv",
            implicit=["scripts/generate_globals.py"],
        )
        writer.build("$builddir/autogenerated/i18n.hpp", "geni18n", "src/i18n.tpl")
        writer.build("$builddir/icon.ico", "copyicon", "resources/placeholder.ico")
        writer.build(
            "$builddir/th06.res",
            "rc",
            inputs="resources/th06.rc",
            implicit="$builddir/icon.ico",
        )
        writer.build(
            "$builddir/th06.def",
            "gendef",
            inputs=[
                "$builddir/" + x + ".obj"
                for x in (main_sources + cxx_sources + pbg3_sources + ["stubs"])
            ],
            implicit=["scripts/gendef.py"],
        )
        objfiles = (
            ["$builddir/" + src + ".obj" for src in main_sources]
            + ["$builddir/" + src + ".obj" for src in cxx_sources]
            + ["$builddir/" + src + ".obj" for src in pbg3_sources]
            + ["$builddir/th06.res", "$builddir/stubs.obj"]
        )
        if build_type in [BuildType.DIFFBUILD, BuildType.DLLBUILD]:
            objfiles += ["$builddir/globals.obj"]

        th06_link_libs = "dxguid.lib d3dx8.lib d3d8.lib dsound.lib winmm.lib kernel32.lib user32.lib dinput8.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib"
        writer.build(
            "$builddir/th06e.exe",
            "link",
            inputs=objfiles,
            variables={
                "link_libs": th06_link_libs,
                "link_flags": "$th06_link_flags /debug /pdb:$builddir/th06e.pdb",
            },
        )

        test_objfiles = (
            ["$builddir/" + src + ".obj" for src in cxx_sources]
            + ["$builddir/" + src + ".obj" for src in pbg3_sources]
            + ["$builddir/" + src + ".obj" for src in test_sources]
            + ["$builddir/stubs.obj"]
        )
        writer.build(
            "$builddir/th06e-tests.exe",
            "link",
            inputs=test_objfiles + ["$builddir/munit.lib"],
            variables={
                "link_libs": th06_link_libs + " $builddir/munit.lib",
                "link_flags": "/debug /pdb:$builddir/th06e.pdb",
            },
        )

        writer.build(
            "$builddir/th06e.dll",
            "link",
            inputs=objfiles + ["$builddir/dllbuild.obj", "$builddir/detours.lib"],
            implicit=["$builddir/th06.def"],
            variables={
                "link_libs": th06_link_libs,
                "link_flags": "/DLL /debug /pdb:$builddir/th06e.pdb /export:DetourFinishHelperProcess,@1,NONAME /def:$builddir/th06.def /export:Direct3DCreate8 /export:malloc /export:calloc /export:realloc /export:??2@YAPAXI@Z /export:free /export:_msize",
            },
        )

        writer.build(
            "$builddir/munit.lib",
            "link",
            inputs=["$builddir/" + s + ".obj" for s in munit_sources],
            variables={"link_flags": "/lib", "link_libs": ""},
        )

        writer.build(
            "$builddir/detours.lib",
            "link",
            inputs=["$builddir/" + s + ".obj" for s in detours_sources],
            variables={"link_flags": "/lib"},
        )

        writer.close()


if __name__ == "__main__":
    configure(BuildType.NORMAL)
