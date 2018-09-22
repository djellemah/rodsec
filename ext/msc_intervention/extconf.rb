require 'mkmf'
pkg_config 'modsecurity'

# don't need piles of debug info. Or maybe we do. Dunno.
CONFIG['debugflags'] = ''

# argument is the directory in which the .so file will be put
create_makefile 'rodsec/msc_intervention'
