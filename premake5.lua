workspace "th06"
configurations { "Debug", "Release" }
location "build"

project "th06"
language "C++"
cppdialect "C++20"
targetname "th06"
targetdir "."
objdir "obj"

files {
    "src/**.cpp",
    "src/**.hpp",
    "src/pbg3/**.cpp"
}
includedirs { "src" }

filter "toolset:gcc"
buildoptions { "-Wall", "-Wextra", "-Wpedantic", "-Wno-gnu-anonymous-struct" }

filter "toolset:clang"
buildoptions { "-Wall", "-Wextra", "-Wpedantic", "-Wno-gnu-anonymous-struct" }

filter { "system:not windows" }
kind "ConsoleApp"
local sdl2_cflags = os.outputof("sdl2-config --cflags") or ""
local sdl2_libs   = os.outputof("sdl2-config --libs")   or ""
if #sdl2_cflags > 0 then buildoptions { sdl2_cflags } end
    if #sdl2_libs   > 0 then linkoptions  { sdl2_libs }   end
        links { "GL", "SDL2_image", "SDL2_ttf", "m" }

        filter { "system:windows" }
        kind "WindowedApp"
        defines { "NOMINMAX", "WIN32_LEAN_AND_MEAN" }

        filter { "system:windows", "action:vs*" }
        warnings "Extra"
        links { "SDL2", "SDL2main", "SDL2_image", "SDL2_ttf", "opengl32" }
        local SDL2_DIR       = os.getenv("SDL2_DIR")
        local SDL2_IMAGE_DIR = os.getenv("SDL2_IMAGE_DIR")
        local SDL2_TTF_DIR   = os.getenv("SDL2_TTF_DIR")
        if SDL2_DIR then
            includedirs { (SDL2_DIR .. "/include") }
            filter { "system:windows", "action:vs*", "architecture:x86_64" }
            libdirs { (SDL2_DIR .. "/lib/x64") }
            filter { "system:windows", "action:vs*", "architecture:x86" }
            libdirs { (SDL2_DIR .. "/lib/x86") }
            filter {}
            end
            if SDL2_IMAGE_DIR then
                includedirs { (SDL2_IMAGE_DIR .. "/include") }
                filter { "system:windows", "action:vs*", "architecture:x86_64" }
                libdirs { (SDL2_IMAGE_DIR .. "/lib/x64") }
                filter { "system:windows", "action:vs*", "architecture:x86" }
                libdirs { (SDL2_IMAGE_DIR .. "/lib/x86") }
                filter {}
                end
                if SDL2_TTF_DIR then
                    includedirs { (SDL2_TTF_DIR .. "/include") }
                    filter { "system:windows", "action:vs*", "architecture:x86_64" }
                    libdirs { (SDL2_TTF_DIR .. "/lib/x64") }
                    filter { "system:windows", "action:vs*", "architecture:x86" }
                    libdirs { (SDL2_TTF_DIR .. "/lib/x86") }
                    filter {}
                    end

                    filter { "system:windows", "action:not vs*" }
                    links { "opengl32" }
                    local pc_cflags = os.outputof("pkg-config --cflags sdl2 SDL2_image SDL2_ttf") or ""
                    local pc_libs   = os.outputof("pkg-config --libs   sdl2 SDL2_image SDL2_ttf") or ""
                    if #pc_cflags > 0 then buildoptions { pc_cflags } end
                        if #pc_libs   > 0 then linkoptions  { pc_libs }   end

                            filter "configurations:Debug"
                            defines { "DEBUG" }
                            symbols "On"
                            optimize "Off"

                            filter "configurations:Release"
                            defines { "NDEBUG" }
                            optimize "Speed"
                            symbols "Off"
