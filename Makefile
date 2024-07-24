CC = clang 
CFLAGS = -Wno-cpp -Wall
OBJ_FILES = main.o eventdatatypes.o
DYN_LYB = -lbsm -lEndpointSecurity
FRAMEWORKS = -framework Foundation -framework Cocoa -framework UniformTypeIdentifiers
EXE = snapturtle
all: $(EXE) codesign

snapturtle: $(OBJ_FILES)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $(EXE) $(FRAMEWORKS) $(DYN_LYB)

main.o: main.m
	$(CC) $(CFLAGS) -c main.m

eventdatatypes.o: eventdatatypes.m
	$(CC) $(CFLAGS) -c eventdatatypes.m

codesign:
	codesign --sign - \
    	--entitlements $(shell pwd)/reformatted.entitlements \
    	--deep $(shell pwd)/$(EXE) \
    	--force

clean:
	rm *.o
