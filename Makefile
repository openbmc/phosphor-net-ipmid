CXX ?= $(CROSS_COMPILE)g++

DAEMON = ipmi
DAEMON_OBJ  = ipmiMain.o \
              ipmiAppUtil.o \
              ipmiCipherInterfaces.o \
              ipmiSockChannelData.o \
              ipmiSession.o \
              ipmiMessage.o \
              ipmiMessageParsers.o \
              ipmiSessionsManager.o \
              ipmiCiphers.o \
              ipmiCommandTable.o \
              ipmiMessageHandler.o \
              ipmiCommModule.o \

DAEMON_EXTRA_LIBS = libssl.so

LDFLAGS += -rdynamic -ldl

CXXFLAGS += -fPIC -Wall

INC_FLAG += $(shell pkg-config --cflags --libs libsystemd) -I. -O2
LIB_FLAG += $(shell pkg-config  --libs libsystemd) -rdynamic
IPMID_PATH ?= -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\"

all:  $(DAEMON)

%.o: %.cpp
	$(CXX) -std=c++14 -c $< $(CXXFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@

$(DAEMON): $(DAEMON_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl -lpthread -lcrypto -lmapper -L.

clean:
	$(RM) $(DAEMON) $(DAEMON_OBJ)
