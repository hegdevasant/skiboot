# If you want to build in another directory copy this file there and
# fill in the following values

#
# Prefix of cross toolchain, if anything
# Example: CROSS= powerpc64-unknown-linux-gnu-
#
CROSS=powerpc64-linux-

#
# Where is the source directory, must be a full path (no ~)
# Example: SRC= /home/me/skiboot
#
SRC=$(CURDIR)

#
# Where to get information about this machine (subdir name)
#
DEVSRC=hdata

#
# default config file, see include config_*.h for more specifics
#
CONFIG := config.h

include $(SRC)/Makefile.main

