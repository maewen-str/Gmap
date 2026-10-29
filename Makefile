CC = gcc
# Added -I./include so gcc knows where your header files live
CFLAGS = -Wall -Wextra -Wimplicit-function-declaration -I./include
LFLAGS =

SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

# Automatically find all .c files in the src/ folder
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Automatically create matching .o file names for the build/ folder
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# The final executable name and location
TARGET = $(BUILD_DIR)/gmap

# Default target
all: $(TARGET)

# Link all compiled .o files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

# Compile each .c file into a .o file inside the build directory
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)/*
