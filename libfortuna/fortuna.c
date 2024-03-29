#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

#include "fortuna.h"

static uchar ctrzero[AESbsize] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

Fortuna*
newfortuna(vlong (*ns)(void))
{
	Fortuna *f;
	int i;

	f = mallocz(sizeof(Fortuna), 1);

	assert(f != nil);

	f->ns = ns;

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

	now = f->ns();
	// if time is standing still we will never reseed..
	assert(now != f->lastseed);

	qlock(f);

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

	return g;
}

static void
ginc(Generator *g)
{
	int i;

	for(i = nelem(g->ctr) - 1; i >= 0; --i){
		g->ctr[i]++;
		if(g->ctr[i] != 0)
			break;
	}
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

	ginc(g);
}

static void
gblocks(Generator *g, int nblocks, uchar *buf, int nbuf)
{
	int i;
	AESstate s;
	uchar *bp;

	// C > 0
	assert(memcmp(g->ctr, ctrzero, AESbsize) != 0);

	assert(nblocks*AESbsize <= nbuf);

	setupAESstate(&s, g->key, sizeof(g->key), nil);

	bp = buf;
	for(i = 0; i < nblocks; i++){
		// r ← r || E(K, C)
		aes_encrypt(s.ekey, s.rounds, g->ctr, bp);
		bp += AESbsize;

		// C = C + 1
		ginc(g);
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

