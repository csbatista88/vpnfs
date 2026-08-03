</$objtype/mkfile

TARG=vpnfs
OFILES=\
	main.$O\
	net_plan9.$O\
	fortinet.$O\

HFILES=\
	src/vpnfs.h\

$TARG: $OFILES
	$LD $LDFLAGS -o $target $OFILES

%.$O: src/%.c
	$CC $CFLAGS src/$stem.c

%.$O: src/drivers/%.c
	$CC $CFLAGS src/drivers/$stem.c

BIN=/$objtype/bin

</sys/src/cmd/mkone
