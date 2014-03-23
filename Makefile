SRC=main.cc
EXE=wlanSniff
WLAN_IF=wlan0
EXE_ARGS=$(WLAN_IF)
DEPS=-lpcap
INC=
CFLAGS=-Wall



all:	$(EXE)

$(EXE):	$(OBJS) $(DEPS) $(SRC)
	$(CXX) $(CFLAGS) $(SRC) -o $(EXE) $(DEPS)

.PHONY: clean

clean: 
	rm -f *.o $(EXE)

monitor:
	sudo ifconfig $(WLAN_IF) down
	sudo iwconfig $(WLAN_IF) mode monitor
	sudo ifconfig $(WLAN_IF) up

run:	$(EXE)
	sudo ./$(EXE) $(EXE_ARGS)


val:	$(EXE)
	sudo valgrind ./$(EXE) $(EXE_ARGS)
