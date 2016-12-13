TARGET_NAME	= final
LIBS		= -lcrypto++ -lssl -lgcrypt

INC_DIR		= include
SRC_DIR		= src
OBJ_DIR		= obj
BIN_DIR		= bin

CC		= g++
SRC_EXT		= cpp
CXXFLAGS	= -std=c++11 -g
INC		= -I$(INC_DIR)

SOURCES		= $(shell find $(SRC_DIR) -name *.$(SRC_EXT))
OBJECTS		= $(patsubst $(SRC_DIR)/%.$(SRC_EXT), $(OBJ_DIR)/%.o, $(SOURCES))
TARGET		= $(BIN_DIR)/$(TARGET_NAME)

$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ -o $@ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.$(SRC_EXT)
	@mkdir -p $(@D)
	$(CC) $^ -o $@ -c $(CXXFLAGS) $(INC)

test: $(TARGET)
	$^

install:
	apt-get install libcrypto++-dev
	apt-get install libssl-dev
	apt-get install libgcrypt20-dev

.PHONY: clean
clean:
	rm -rf *~ $(OBJ_DIR) $(BIN_DIR)
