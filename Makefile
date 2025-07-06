CXX = clang++
ODIR=obj
SDIR=src
PBG_SDIR=src/pbg3
CXXFLAGS = `sdl2-config --cflags` -I./$(SDIR)/ -Wall -Wextra -Wpedantic -Wno-gnu-anonymous-struct -g -std=c++20 -DDEBUG
LDFLAGS = `sdl2-config --libs` -lGL -lSDL2_image -lSDL2_ttf -lm
DEPS = GameWindow.hpp
_OBJ = AnmManager.o AsciiManager.o BombData.o BulletData.o BulletManager.o Chain.o Controller.o \
	   EclManager.o EffectManager.o Ending.o EnemyEclInstr.o EnemyManager.o FileSystem.o  GameErrorContext.o \
	   GameManager.o GameWindow.o Gui.o ItemManager.o main.o MainMenu.o MusicRoom.o Player.o ReplayManager.o \
	   ResultScreen.o Rng.o ScreenEffect.o SoundPlayer.o Stage.o Supervisor.o TextHelper.o utils.o ZunTimer.o 
OBJ  = $(patsubst %,$(ODIR)/%,$(_OBJ))
_PBG_OBJ = FileAbstraction.o IPbg3Parser.o Pbg3Archive.o Pbg3Parser.o
PBG_OBJ = $(patsubst %,$(ODIR)/%,$(_PBG_OBJ))
default: th06

$(OBJ): $(ODIR)/%.o: $(SDIR)/%.cpp $(SDIR)/$(DEPS)
		$(CXX) -c -o $@ $< $(CXXFLAGS)
$(PBG_OBJ): $(ODIR)/%.o: $(PBG_SDIR)/%.cpp
		$(CXX) -c -o $@ $< $(CXXFLAGS)
th06: $(OBJ) $(PBG_OBJ)
		$(CXX) -o $@ $^ $(LDFLAGS)
clean:
		rm -rf $(ODIR)/*
		rm ./th06
