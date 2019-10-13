LD=link
MAKE=nmake
RM=DEL
CP=COPY

!IFDEF PLATFORM
PLAT=$(PLATFORM)
!ELSEIF TARGET_CPU
PLAT=$(TARGET_CPU)
!ELSE
!ERROR Target platform cannot be deduced. Make sure the MS SDK building \
environment is set.
!ENDIF

!IF "$(PLAT)"=="x86"
PLAT_ALT=i386
!ELSEIF "$(PLAT)"=="x64"
PLAT_ALT=amd64
!ENDIF

!IF EXIST("$(WINDOWSSDKDIR)\Debuggers")
WINDBG_DIR=$(WINDOWSSDKDIR)\Debuggers
WINDBGSDK_INC=$(WINDBG_DIR)\inc
WINDBGSDK_LIB=$(WINDBG_DIR)\lib\$(PLAT)
WINDBG_EXT=$(WINDBG_DIR)\$(PLAT)\winext
!ELSEIF EXIST("$(PROGRAMFILES)\Debugging Tools for Windows ($(PLAT))")
WINDBG_DIR=$(PROGRAMFILES)\Debugging Tools for Windows ($(PLAT))
WINDBGSDK_INC=$(WINDBG_DIR)\sdk\inc
WINDBGSDK_LIB=$(WINDBG_DIR)\sdk\lib\$(PLAT_ALT)
WINDBG_EXT=$(WINDBG_DIR)\winext
!ELSEIF EXIST("$(PROGRAMFILES) (x86)\Debugging Tools for Windows ($(PLAT))")
WINDBG_DIR=$(PROGRAMFILES) (x86)\Debugging Tools for Windows ($(PLAT))
WINDBGSDK_INC=$(WINDBG_DIR)\sdk\inc
WINDBGSDK_LIB=$(WINDBG_DIR)\sdk\lib\$(PLAT_ALT)
WINDBG_EXT=$(WINDBG_DIR)\winext
!ELSE
!ERROR Cannot find WinDbg installation directory.
!ENDIF

CPPFLAGS_CMN=-I"$(WINDBGSDK_INC)"
CPPFLAGS=$(CPPFLAGS_CMN) -Yucommon.h
LDFLAGS=-DLL -LIBPATH:"$(WINDBGSDK_LIB)" dbgeng.lib

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

distclean: clean
	$(RM) *.pch

install: dumpext.dll
	$(CP) $** "$(WINDBG_EXT)"

# precompiled common headers
common.obj: common.cpp
	$(CPP) -c $(CPPFLAGS_CMN) -Yc$*.h $**

dumpext.dll: $(OBJS)
	$(LD) -DEF:dumpext.def $(LDFLAGS) $** /out:$@
