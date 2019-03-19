RM ?= rm -r
CP ?= cp -r
V ?= 0

ifeq ($(V),0)
	Q = @
	
	TRACE_CXX = @echo "  CXX       $^"
	TRACE_CC = @echo "  CC        $^"
	TRACE_AR = @echo "  AR        $^"
	TRACE_MKDIR = @echo "  MKDIR     $^"
	
	ARFLAGS = rs
else
	ARFLAGS = rvs
endif

SRCFILES = kpabe.cpp kpabe_c_wrapper.cpp
DIR_SRCFILES = ${addprefix $(SRCDIR)/,$(SRCFILES)}
OBJFILES = ${patsubst %.cpp,%.o,$(SRCFILES)}
HFILES = kpabe.hpp kpabe.h
DIR_HFILES = ${addprefix $(SRCDIR)/,$(HFILES)}

all: libyao.a

install: $(DIR_HFILES) libyao.a $(PREFIX)/include/ $(PREFIX)/lib/
	$(Q)$(CP) $(DIR_HFILES) $(PREFIX)/include/
	$(Q)$(CP) libyao.a $(PREFIX)/lib/

clean:
	$(RM) *.o
	
libyao.a: $(OBJFILES)
	$(TRACE_AR)
	$(Q)$(AR) $(ARFLAGS) $@ $^
	
%/:
	$(TRACE_MKDIR)
	$(Q)$(MKDIR) $@

%.o: $(SRCDIR)/%.c
	$(TRACE_CC)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -c $^ -o $@
	
%.o: $(SRCDIR)/%.cpp
	$(TRACE_CXX)
	$(Q)$(CXX) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) -c $^ -o $@
	
	