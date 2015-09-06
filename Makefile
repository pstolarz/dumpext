LD=link
MAKE=nmake
RM=DEL
CP=COPY

!IF "$(TARGET_CPU)"=="x86"
CPU_DIR=i386
DIR_PSFIX=(x86)
!ELSEIF "$(TARGET_CPU)"=="x64"
CPU_DIR=amd64
DIR_PSFIX=(x64)
!ELSEIF "$(TARGET_CPU)"=="IA64"
CPU_DIR=ia64
DIR_PSFIX=(x64)
!ENDIF

!IFNDEF WINDBG_DIR
WINDBG_DIR=%ProgramFiles%\Debugging Tools for Windows $(DIR_PSFIX)
!ENDIF

!IF !DEFINED(CPU_DIR)
!ERROR Target platform can't be deduced. Make sure the MS SDK building \
environment is set and WINDBG_DIR is defined for non standard WinDbg \
installation location.
!ENDIF

INC=-I "$(WINDBG_DIR)\sdk\inc"
CPPFLAGS_CMN=$(INC)
CPPFLAGS=$(CPPFLAGS_CMN) -Yucommon.h

LIB_DIR=-LIBPATH:"$(WINDBG_DIR)\sdk\lib\$(CPU_DIR)"
LIBS=dbgeng.lib
LDFLAGS=-DLL $(LIB_DIR) $(LIBS)

OBJS = rdflags.obj \
       common.obj \
       config.obj \
       pebase.obj \
       resrc.obj \
       imports.obj \
       except.obj \
       dumpext.obj

all: dumpext.dll

clean:
	$(RM) *.obj *.dll *.exp *.lib

cleanall: clean
	$(RM) *.pch

install: dumpext.dll
	$(CP) $** "$(WINDBG_DIR)\winext"

# precompiled common headers
common.obj: common.cpp
	$(CPP) -c $(CPPFLAGS_CMN) -Yc$*.h $**

dumpext.dll: $(OBJS)
	$(LD) -DEF:dumpext.def $(LDFLAGS) $** /out:$@
