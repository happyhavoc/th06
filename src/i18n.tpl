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

// EN
#define TH_EN_CONFIG_FILE "th06.cfg"
#define TH_EN_WINDOW_TITLE "Touhou Koumakyou　〜 the Embodiment of Scarlet Devil"
#define TH_EN_ERR_ALREADY_RUNNING "Touhou cannot be started\n"
#define TH_EN_ERR_D3D_COULD_NOT_CREATE_OBJ "Direct3D object could not be created for some reason\n"
#define TH_EN_ERR_LOGGER_START "Logger started --------------------------------------------- \n"
#define TH_EN_ERR_LOGGER_END "---------------------------------------------------------- \n"
#define TH_EN_ERR_NO_PAD_FOUND "Unfortunately, there doesn't seem to be a pad that can be used.\n"
#define TH_EN_ERR_OPTION_CHANGED_RESTART "An option that requires a restart has been changed.\n"

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
