</$objtype/mkfile

TARG=rngd
LIB=libfortuna/libfortuna.$O.a
OFILES=rngd.$O
HFILES=libfortuna/fortuna.h

BIN=/$objtype/bin

</sys/src/cmd/mkmany

CFLAGS=-Ilibfortuna

$LIB:V:
	cd libfortuna
	mk

$O.rngd:	rngd.$O $LIB
	$LD $LDFLAGS -o $target $prereq

$O.test:	test.$O $LIB
	$LD $LDFLAGS -o $target $prereq

clean nuke:V:
	@{ cd libfortuna; mk $target }
	rm -f *.[$OS] [$OS].* $TARG

