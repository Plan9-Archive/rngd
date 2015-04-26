#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

#include "fortuna.h"

Fortuna*
newfortuna(void)
{
	Fortuna *f;
	int i;

	f = mallocz(sizeof(Fortuna), 1);

	for(i = 0; i < nelem(f->pools); i++)
		f->pools[i] = newepool();

	f->nseed = 0;

	f->g = newgenerator();

	return f;
}

void
frandom(Fortuna *f, uchar *buf, int nbuf)
{
	vlong now;
	int i, x, npool;
	uchar *bp;

	if(buf == nil || nbuf <= 0)
		return;

	qlock(f);
	genrandom(buf, nbuf);

	now = nsec();

	if(eplen(f->pools[0]) >= FPOOLMINSIZE && (now - f->lastseed) > 100000000LL){
		f->lastseed = now;
		f->nseed++;
		memset(f->newseed, 0, sizeof(f->newseed));
		npool = 0;
		bp = f->newseed;
		for(i = 0; i < nelem(f->pools); i++){
			x = 1 << i;
			if(f->nseed % x == 0){
				npool++;
				epsum(f->pools[i], bp);
				memset(f->pools[i], 0, sizeof(EPool));
				bp += SHA2_256dlen;
			}
		}

		greseed(f->g, f->newseed, npool*SHA2_256dlen);
	}

	grandom(f->g, buf, nbuf);

	qunlock(f);
}

void
faddentropy(Fortuna *f, u8int src, u8int pool, uchar *buf, u8int nbuf)
{
	EPool *p;

	assert(nbuf >= 1 && nbuf <= 32);
	assert(pool <= FPOOLCOUNT);

	qlock(f);

	p = f->pools[pool];
	epadd(p, &src, 1);
	epadd(p, &nbuf, 1);
	epadd(p, buf, nbuf);

	qunlock(f);
}

void
fclose(Fortuna *f)
{
	gclose(f->g);
	free(f);
}

Generator*
newgenerator(void)
{
	Generator *g;

	g = mallocz(sizeof(Generator), 1);
	g->counter = mpnew(128);

	mpassign(mpzero, g->counter);

	return g;
}

void
greseed(Generator *g, uchar *seed, int nseed)
{
	DigestState *ds;

	if(seed == nil || nseed <= 0)
		return;

	// K || s
	ds = sha2_256(g->key, sizeof(g->key), nil, nil);
	sha2_256(seed, nseed, g->key, ds);

	mpadd(g->counter, mpone, g->counter);
}

static void
gblocks(Generator *g, int nblocks, uchar *buf, int nbuf)
{
	int i;
	AESstate s;
	uchar ctr[AESbsize], *bp;

	// C > 0
	assert(mpcmp(g->counter, mpzero) == 1);

	assert(nblocks*AESbsize <= nbuf);

	setupAESstate(&s, g->key, sizeof(g->key), nil);

	bp = buf;
	for(i = 0; i < nblocks; i++){
		// r ← r || E(K, C)
		mptole(g->counter, ctr, AESbsize, nil);
		aesCBCencrypt(ctr, AESbsize, &s);
		memcpy(bp, ctr, AESbsize);
		bp += AESbsize;

		// C = C + 1
		mpadd(g->counter, mpone, g->counter);
	}
}

void
grandom(Generator *g, uchar *buf, int n)
{
	int nblk;
	uchar rnd[AESbsize], *bp;

	// 0 ≤ n ≤ 2²⁰
	assert(n >= 0 && n <= 2<<19);

	// r ← first-n-bytes(GenerateBlocks(G, n/16))
	bp = buf;
	nblk = n/AESbsize;
	n -= nblk*AESbsize;

	if(nblk > 0){
		gblocks(g, nblk, bp, nblk*AESbsize);
		bp += nblk*AESbsize;
	}

	if(n > 0){
		gblocks(g, 1, rnd, sizeof(rnd));
		memcpy(bp, rnd, n);
	}

	// K ← GenerateBlocks(G, 2)
	gblocks(g, 2, g->key, sizeof(g->key));
}

void
gclose(Generator *g)
{
	mpfree(g->counter);
	memset(g, 0, sizeof(Generator));
	free(g);
}

EPool*
newepool(void)
{
	return mallocz(sizeof(EPool), 1);
}

void
epadd(EPool *p, uchar *buf, int nbuf)
{
	sha2_256(buf, nbuf, nil, p);
	p->size += nbuf;
}

u64int
eplen(EPool *p)
{
	return p->size;
}

void
epsum(EPool *p, uchar *buf)
{
	sha2_256(nil, 0, buf, p);
}
