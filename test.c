#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

#include "fortuna.h"

Fortuna *f;

void
testgenerator(void)
{
	uchar buf[32];

	memset(buf, 0, sizeof(buf));
	grandom(f->g, buf, sizeof(buf));
	print("random: %02d %.*H\n", sizeof(buf), sizeof(buf), buf);
}

void
main(int, char**)
{
	fmtinstall('H', encodefmt);

	f = newfortuna(nsec);

	print("key %.*H\n", sizeof(f->g->key), f->g->key);
	print("counter %.*H\n", sizeof(f->g->ctr), f->g->ctr);

	greseed(f->g, (uchar*)"hello world", 11);

	print("key %.*H\n", sizeof(f->g->key), f->g->key);
	print("counter %.*H\n", sizeof(f->g->ctr), f->g->ctr);

	testgenerator();

	fclose(f);

	exits(nil);
}
