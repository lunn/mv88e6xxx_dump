
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=error \
	CFLAGS="-O2 -D_FORTIFY_SOURCE=2"

ACLOCAL_AMFLAGS = -I m4

################################################################################

DISTCLEANFILES = ChangeLog
doc_DATA       = ChangeLog

# Build changelog from git history
.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d $(top_srcdir)/.git; then \
		prev=$$(git describe --tags --always --match '[0-9]*' 2> /dev/null) ; \
		for tag in $$(git log --decorate=full --simplify-by-decoration --pretty=oneline HEAD | sed -r -e 's#^[^\(]*\(([^\)]*)\).*$$#\1#' -e 's#,#\n#g' | grep 'tag:' | sed -r -e 's#[[:space:]]*tag:[[:space:]]*##'); do \
			if [ x"$$prev" = x ]; then prev=$$tag ; fi ; \
			if [ x"$$prev" = x"$$tag" ]; then continue; fi ; \
			echo "$$prev [$$(git log $$prev -1 --pretty=format:'%ai')]:" ; \
			echo "" ; \
			git log --pretty=' - [%h] %s' $$tag..$$prev ; \
			echo "" ; \
			prev=$$tag ; \
		done > $@ ; \
	else \
		touch $@ ; \
	fi

EXTRA_DIST = README

################################################################################

bin_PROGRAMS = mv88e6xxx_dump

mv88e6xxx_dump_SOURCES =  \
	libnetlink.h     \
	mnlg.h           \
	prettymsg.h      \
	utils.h          \
	desc-devlink.c   \
	desc-genlctrl.c  \
	libnetlink.c     \
	mnlg.c           \
	prettymsg.c      \
	mv88e6xxx_dump.c \
	$(NULL)

mv88e6xxx_dump_CPPFLAGS = \
        -I$(top_srcdir) \
        -I$(top_builddir) \
        $(LIBMNL_CFLAGS) \
        $(NULL)

mv88e6xxx_dump_LDFLAGS = \
        $(LIBMNL_LIBS) \
        $(NULL)

