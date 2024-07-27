CC = clang 
CFLAGS = -Wno-cpp -Wall
OBJ_DIR = build
SRC_FILES = main.m eventdatatypes.m shared.m
OBJ_FILES = $(addprefix $(OBJ_DIR)/, $(notdir $(SRC_FILES:.m=.o)))
DYN_LIB = -lbsm -lEndpointSecurity
FRAMEWORKS = -framework Foundation -framework Cocoa -framework UniformTypeIdentifiers
EXE = snapturtle

$(shell mkdir -p $(OBJ_DIR))

all: $(EXE) codesign

$(EXE): $(OBJ_FILES)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $(EXE) $(DYN_LIB) $(FRAMEWORKS) 

$(OBJ_DIR)/%.o: %.m
	$(CC) $(CFLAGS) -c $< -o $@

codesign:
	codesign --sign - \
    	--entitlements $(shell pwd)/reformatted.entitlements \
    	--deep $(shell pwd)/$(EXE) \
    	--force

clean:
	rm -rf $(OBJ_DIR) $(EXE)
