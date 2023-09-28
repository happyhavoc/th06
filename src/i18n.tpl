#pragma once

// #define TH_LANG TH_JP
#define TH_LANG TH_EN

// JP
#define TH_JP_CONFIG_FILE "東方紅魔郷.cfg"
#define TH_JP_WINDOW_TITLE "東方紅魔郷　〜 the Embodiment of Scarlet Devil"
#define TH_JP_ERR_ALREADY_RUNNING "二つは起動できません\n"
#define TH_JP_ERR_D3D_COULD_NOT_CREATE_OBJ "Direct3D オブジェクトは何故か作成出来なかった\n"
#define TH_JP_ERR_LOGGER_START "東方動作記録 --------------------------------------------- \n"
#define TH_JP_ERR_LOGGER_END "---------------------------------------------------------- \n"
#define TH_JP_ERR_NO_PAD_FOUND "使えるパッドが存在しないようです、残念\n"
#define TH_JP_ERR_OPTION_CHANGED_RESTART "再起動を要するオプションが変更されたので再起動します\n"
#define TH_JP_ERR_SCREEN_INIT_32BITS "初回起動、画面を 32Bits で初期化しました\n"
#define TH_JP_ERR_SCREEN_INIT_16BITS "初回起動、画面を 16Bits で初期化しました\n"
#define TH_JP_ERR_SET_REFRESH_RATE_60HZ "リフレッシュレートを60Hzに変更します\n"
#define TH_JP_ERR_TL_HAL_UNAVAILABLE "T&L HAL は使用できないようです\n"
#define TH_JP_ERR_HAL_UNAVAILABLE "HAL も使用できないようです\n"
#define TH_JP_ERR_D3D_INIT_FAILED "Direct3D の初期化に失敗、これではゲームは出来ません\n"
#define TH_JP_ERR_BACKBUFFER_NONLOCKED "バックバッファをロック不可能にしてみます\n"
#define TH_JP_ERR_CANT_CHANGE_REFRESH_RATE_FORCE_VSYNC "リフレッシュレートが変更できません、vsync 非同期に変更します\n"
#define TH_JP_USING_REF_MODE "REF で動作しますが、重すぎて恐らくゲームになりません...\n"
#define TH_JP_USING_HAL_MODE "HAL で動作します\n"
#define TH_JP_USING_TL_HAL_MODE "T&L HAL で動作しま〜す\n"
#define TH_JP_ERR_NO_SUPPORT_FOR_D3DTEXOPCAPS_ADD                                                                      \
    "D3DTEXOPCAPS_ADD をサポートしていません、色加算エミュレートモードで動作します\n"
#define TH_JP_ERR_CANT_FORCE_60FPS_NO_ASYNC_FLIP                                                                       \
    "ビデオカードが非同期フリップをサポートしていません、Force60Frameで動作できません\n"
#define TH_JP_ERR_D3DFMT_A8R8G8B8_UNSUPPORTED "D3DFMT_A8R8G8B8 をサポートしていません、減色モードで動作します\n"
#define TH_JP_ERR_CONFIG_NOT_FOUND "コンフィグデータが見つからないので初期化しました\n"
#define TH_JP_ERR_CONFIG_CORRUPTED "コンフィグデータが破壊されていたので再初期化しました\n"
#define TH_JP_ERR_NO_WAVE_FILE "wave データが無いので、midi にします\n"
#define TH_JP_ERR_NO_VERTEX_BUFFER "頂点バッファの使用を抑制します\n"
#define TH_JP_ERR_NO_FOG "フォグの使用を抑制します\n"
#define TH_JP_ERR_USE_16BIT_TEXTURES "16Bit のテクスチャの使用を強制します\n"
#define TH_JP_ERR_FORCE_BACKBUFFER_CLEAR "バックバッファの消去を強制します\n"
#define TH_JP_ERR_DONT_RENDER_ITEMS "ゲーム周りのアイテムの描画を抑制します\n"
#define TH_JP_ERR_NO_GOURAUD_SHADING "グーローシェーディングを抑制します\n"
#define TH_JP_ERR_NO_DEPTH_TESTING "デプステストを抑制します\n"
#define TH_JP_ERR_FORCE_60FPS_MODE "60フレーム強制モードにします\n"
#define TH_JP_ERR_NO_TEXTURE_COLOR_COMPOSITING "テクスチャの色合成を抑制します\n"
#define TH_JP_ERR_LAUNCH_WINDOWED "ウィンドウモードで起動します\n"
#define TH_JP_ERR_FORCE_REFERENCE_RASTERIZER "リファレンスラスタライザを強制しますn"
#define TH_JP_ERR_DO_NOT_USE_DIRECTINPUT "パッド、キーボードの入力に DirectInput を使用しません\n"
#define TH_JP_ERR_FILE_CANNOT_BE_EXPORTED "ファイルが書き出せません %s\n"
#define TH_JP_ERR_FOLDER_HAS_WRITE_PROTECT_OR_DISK_FULL                                                                \
    "フォルダが書込み禁止属性になっているか、ディスクがいっぱいいっぱいになってませんか？\n"

// EN
#define TH_EN_CONFIG_FILE "th06.cfg"
#define TH_EN_WINDOW_TITLE "Touhou Koumakyou　〜 the Embodiment of Scarlet Devil"
#define TH_EN_ERR_ALREADY_RUNNING "Touhou cannot be started\n"
#define TH_EN_ERR_D3D_COULD_NOT_CREATE_OBJ "Direct3D object could not be created for some reason\n"
#define TH_EN_ERR_LOGGER_START "Logger started --------------------------------------------- \n"
#define TH_EN_ERR_LOGGER_END "---------------------------------------------------------- \n"
#define TH_EN_ERR_NO_PAD_FOUND "Unfortunately, there doesn't seem to be a pad that can be used.\n"
#define TH_EN_ERR_OPTION_CHANGED_RESTART "An option that requires a restart has been changed.\n"
#define TH_EN_ERR_SCREEN_INIT_32BITS "First startup, screen initialized with 32Bits.\n"
#define TH_EN_ERR_SCREEN_INIT_16BITS "First startup, screen initialized with 16Bits.\n"
#define TH_EN_ERR_SET_REFRESH_RATE_60HZ "Setting the refresh rate to 60Hz.\n"
#define TH_EN_ERR_TL_HAL_UNAVAILABLE "T&L HAL does not appear to be available.\n"
#define TH_EN_ERR_HAL_UNAVAILABLE "HAL does not appear to be available either.\n"
#define TH_EN_ERR_D3D_INIT_FAILED "Direct3D initialization failed, the game cannot be played.\n"
#define TH_EN_ERR_BACKBUFFER_NONLOCKED "Retrying to create D3D context without locked backbuffer.\n"
#define TH_EN_ERR_CANT_CHANGE_REFRESH_RATE_FORCE_VSYNC "Unable to set refresh rate, enabling vsync.\n"
#define TH_EN_USING_REF_MODE "Using REF mode, expect heavy lag...\n"
#define TH_EN_USING_HAL_MODE "Using HAL mode.\n"
#define TH_EN_USING_TL_HAL_MODE "Using T&L HAL mode.\n"
#define TH_EN_ERR_NO_SUPPORT_FOR_D3DTEXOPCAPS_ADD                                                                      \
    "Does not support D3DTEXOPCAPS_ADD, operates in color additive emulation mode.\n"
#define TH_EN_ERR_CANT_FORCE_60FPS_NO_ASYNC_FLIP                                                                       \
    "Video card does not support asynchronous flipping, cannot work with Force60Frame.\n"
#define TH_EN_ERR_D3DFMT_A8R8G8B8_UNSUPPORTED "D3DFMT_A8R8G8B8 not supported, operating in reduced color mode.\n"
#define TH_EN_ERR_CONFIG_NOT_FOUND "Config not found, initializing with default values.\n"
#define TH_EN_ERR_CONFIG_CORRUPTED "Config corrupted, reinitializing with default values.\n"
#define TH_EN_ERR_NO_WAVE_FILE "There is no wave data, so I'll make it midi!\n"
#define TH_EN_ERR_NO_VERTEX_BUFFER "Suppressing the use of the vertex buffer.\n"
#define TH_EN_ERR_NO_FOG "Suppressing the use of fog.\n"
#define TH_EN_ERR_USE_16BIT_TEXTURES "Enforces the use of 16Bit textures.\n"
#define TH_EN_ERR_FORCE_BACKBUFFER_CLEAR "Force clearing of the back buffer.\n"
#define TH_EN_ERR_DONT_RENDER_ITEMS "Suppress the rendering of items around the game.\n"
#define TH_EN_ERR_NO_GOURAUD_SHADING "Suppress gouraud shading.\n"
#define TH_EN_ERR_NO_DEPTH_TESTING "Suppress depth testing.\n"
#define TH_EN_ERR_FORCE_60FPS_MODE "Force 60FPS mode.\n"
#define TH_EN_ERR_NO_TEXTURE_COLOR_COMPOSITING "Suppress texture color compositing.\n"
#define TH_EN_ERR_LAUNCH_WINDOWED "Launch in windowed mode.\n"
#define TH_EN_ERR_FORCE_REFERENCE_RASTERIZER "Force reference rasterizer.\n"
#define TH_EN_ERR_DO_NOT_USE_DIRECTINPUT "Do not use DirectInput for pad and keyboard input.\n"
#define TH_EN_ERR_FILE_CANNOT_BE_EXPORTED "File cannot be exported %s.\n"
#define TH_EN_ERR_FOLDER_HAS_WRITE_PROTECT_OR_DISK_FULL "Folder has write protect attribute or disk full?\n"

#define TH_CONCAT_HELPER(x, y) x##y

#define TH_MAKE_LANG_STR(lang, id) TH_CONCAT_HELPER(lang, id)

#define TH_CONFIG_FILE TH_MAKE_LANG_STR(TH_LANG, _CONFIG_FILE)
#define TH_WINDOW_TITLE TH_MAKE_LANG_STR(TH_LANG, _WINDOW_TITLE)
#define TH_ERR_ALREADY_RUNNING TH_MAKE_LANG_STR(TH_LANG, _ERR_ALREADY_RUNNING)
#define TH_ERR_D3D_ERR_COULD_NOT_CREATE_OBJ TH_MAKE_LANG_STR(TH_LANG, _ERR_D3D_COULD_NOT_CREATE_OBJ)
#define TH_ERR_LOGGER_START TH_MAKE_LANG_STR(TH_LANG, _ERR_LOGGER_START)
#define TH_ERR_LOGGER_END TH_MAKE_LANG_STR(TH_LANG, _ERR_LOGGER_END)
#define TH_ERR_NO_PAD_FOUND TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_PAD_FOUND)
#define TH_ERR_OPTION_CHANGED_RESTART TH_MAKE_LANG_STR(TH_LANG, _ERR_OPTION_CHANGED_RESTART)
#define TH_ERR_SCREEN_INIT_32BITS TH_MAKE_LANG_STR(TH_LANG, _ERR_SCREEN_INIT_32BITS)
#define TH_ERR_SCREEN_INIT_16BITS TH_MAKE_LANG_STR(TH_LANG, _ERR_SCREEN_INIT_16BITS)
#define TH_ERR_SET_REFRESH_RATE_60HZ TH_MAKE_LANG_STR(TH_LANG, _ERR_SET_REFRESH_RATE_60HZ)
#define TH_ERR_TL_HAL_UNAVAILABLE TH_MAKE_LANG_STR(TH_LANG, _ERR_TL_HAL_UNAVAILABLE)
#define TH_ERR_HAL_UNAVAILABLE TH_MAKE_LANG_STR(TH_LANG, _ERR_HAL_UNAVAILABLE)
#define TH_ERR_D3D_INIT_FAILED TH_MAKE_LANG_STR(TH_LANG, _ERR_D3D_INIT_FAILED)
#define TH_ERR_BACKBUFFER_NONLOCKED TH_MAKE_LANG_STR(TH_LANG, _ERR_BACKBUFFER_NONLOCKED)
#define TH_ERR_CANT_CHANGE_REFRESH_RATE_FORCE_VSYNC TH_MAKE_LANG_STR(TH_LANG, _ERR_CANT_CHANGE_REFRESH_RATE_FORCE_VSYNC)
#define TH_USING_REF_MODE TH_MAKE_LANG_STR(TH_LANG, _USING_REF_MODE)
#define TH_USING_HAL_MODE TH_MAKE_LANG_STR(TH_LANG, _USING_HAL_MODE)
#define TH_USING_TL_HAL_MODE TH_MAKE_LANG_STR(TH_LANG, _USING_TL_HAL_MODE)
#define TH_ERR_NO_SUPPORT_FOR_D3DTEXOPCAPS_ADD TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_SUPPORT_FOR_D3DTEXOPCAPS_ADD)
#define TH_ERR_CANT_FORCE_60FPS_NO_ASYNC_FLIP TH_MAKE_LANG_STR(TH_LANG, _ERR_CANT_FORCE_60FPS_NO_ASYNC_FLIP)
#define TH_ERR_D3DFMT_A8R8G8B8_UNSUPPORTED TH_MAKE_LANG_STR(TH_LANG, _ERR_D3DFMT_A8R8G8B8_UNSUPPORTED)
#define TH_ERR_CONFIG_NOT_FOUND TH_MAKE_LANG_STR(TH_LANG, _ERR_CONFIG_NOT_FOUND)
#define TH_ERR_CONFIG_CORRUPTED TH_MAKE_LANG_STR(TH_LANG, _ERR_CONFIG_CORRUPTED)
#define TH_ERR_NO_WAVE_FILE TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_WAVE_FILE)
#define TH_ERR_NO_VERTEX_BUFFER TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_VERTEX_BUFFER)
#define TH_ERR_NO_FOG TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_FOG)
#define TH_ERR_USE_16BIT_TEXTURES TH_MAKE_LANG_STR(TH_LANG, _ERR_USE_16BIT_TEXTURES)
#define TH_ERR_FORCE_BACKBUFFER_CLEAR TH_MAKE_LANG_STR(TH_LANG, _ERR_FORCE_BACKBUFFER_CLEAR)
#define TH_ERR_DONT_RENDER_ITEMS TH_MAKE_LANG_STR(TH_LANG, _ERR_DONT_RENDER_ITEMS)
#define TH_ERR_NO_GOURAUD_SHADING TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_GOURAUD_SHADING)
#define TH_ERR_NO_DEPTH_TESTING TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_DEPTH_TESTING)
#define TH_ERR_FORCE_60FPS_MODE TH_MAKE_LANG_STR(TH_LANG, _ERR_FORCE_60FPS_MODE)
#define TH_ERR_NO_TEXTURE_COLOR_COMPOSITING TH_MAKE_LANG_STR(TH_LANG, _ERR_NO_TEXTURE_COLOR_COMPOSITING)
#define TH_ERR_LAUNCH_WINDOWED TH_MAKE_LANG_STR(TH_LANG, _ERR_LAUNCH_WINDOWED)
#define TH_ERR_FORCE_REFERENCE_RASTERIZER TH_MAKE_LANG_STR(TH_LANG, _ERR_FORCE_REFERENCE_RASTERIZER)
#define TH_ERR_DO_NOT_USE_DIRECTINPUT TH_MAKE_LANG_STR(TH_LANG, _ERR_DO_NOT_USE_DIRECTINPUT)
#define TH_ERR_FILE_CANNOT_BE_EXPORTED TH_MAKE_LANG_STR(TH_LANG, _ERR_FILE_CANNOT_BE_EXPORTED)
#define TH_ERR_FOLDER_HAS_WRITE_PROTECT_OR_DISK_FULL                                                                   \
    TH_MAKE_LANG_STR(TH_LANG, _ERR_FOLDER_HAS_WRITE_PROTECT_OR_DISK_FULL)
