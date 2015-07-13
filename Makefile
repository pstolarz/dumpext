RM=del
LD=link
MAKE=nmake

WINDBG_DIR=C:/Program Files/Debugging Tools for Windows (x64)

INC=-I "$(WINDBG_DIR)/sdk/inc"
CPPFLAGS_CMN=$(INC)
CPPFLAGS=$(CPPFLAGS_CMN) -Yucommon.h

LIB_DIR=-LIBPATH:"$(WINDBG_DIR)/sdk/lib/amd64"
LIBS=dbgeng.lib
LDFLAGS=-DLL $(LIB_DIR) $(LIBS)

OBJS =  rdflags.obj \
        common.obj  \
        config.obj  \
        pebase.obj  \
        resrc.obj   \
        imports.obj \
        except.obj  \
        dumpext.obj

all: dumpext.dll

clean:
	$(RM) *.obj *.dll *.exp *.lib

cleanall: clean
	$(RM) *.pch

# precompiled common headers
common.obj: common.cpp
	$(CPP) -c $(CPPFLAGS_CMN) -Yc$*.h $**

dumpext.dll: $(OBJS)
	$(LD) -DEF:dumpext.def $(LDFLAGS) $** /out:$@
