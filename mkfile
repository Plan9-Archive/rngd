</$objtype/mkfile

TARG=rngd

OFILES=\
	rngd.$O\
	fortuna.$O

BIN=/$objtype/bin

</sys/src/cmd/mkmany

$O.rngd:	rngd.$O fortuna.$O
	$LD -o $target $prereq

$O.test:	test.$O fortuna.$O
	$LD -o $target $prereq

