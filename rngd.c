#include <u.h>
#include <libc.h>
#include <auth.h>
#include <mp.h>
#include <libsec.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>

#include "fortuna.h"

static int debug = 0;
static long exiting = 0;
static long nproc = 0;
static Channel *writes;
static Fortuna *fortuna;

enum 
{
	Qroot,
	Qrandom,
	Nqid,
};

static int
filefield(char *file, int nf)
{
	char *f[10], buf[512];
	int fd, n;

	fd = open(file, OREAD);
	if(fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf));
	close(fd);

	if(n <= 0)
		return -1;

	n = tokenize(buf, f, nelem(f));
	if(n < nf)
		return -1;

	return atoi(f[nf]);
}

// 
static int
truerandom(uchar *buf, int nbuf)
{
	int fd, n;
	fd = open("#c/random", OREAD);
	if(fd <= 0)
		return -1;

	nbuf = nbuf >= 32 ? 32 : nbuf;

	n = read(fd, buf, nbuf);
	close(fd);
	return n;
}

// context switches
static int
contextswitches(uchar *buf, int nbuf)
{
	union {
		u32int i;
		uchar b[4];
	} u;

	assert(buf != nil);
	assert(nbuf > 0);

	u.i = filefield("#c/sysstat", 1);

	nbuf  = nbuf >= 4 ? 4 : nbuf;
	memcpy(buf, u.b, nbuf);
	return nbuf;
};

// sha hash nanosecond timestamp
static int
nanoseconds(uchar *buf, int nbuf)
{
	int fd, n;
	char ts[128], *f[4];
	uchar sha[SHA2_256dlen];
	union {
		uvlong u;
		uchar b[sizeof(uvlong)];
	} u;

	fd = open("#c/time", OREAD);
	if(fd < 0)
		return -1;

	n = read(fd, ts, sizeof(ts));
	close(fd);
	if(n <= 0)
		return -1;

	if(tokenize(ts, f, nelem(f)) != nelem(f))
		return -1;

	u.u = strtoull(f[2], nil, 0);
	sha2_256(u.b, sizeof(u.b), sha, nil);
	nbuf = nbuf >= SHA2_256dlen ? SHA2_256dlen : nbuf;
	memcpy(buf, sha, nbuf);
	return nbuf;
}

// handler for writes to 'random' file
static int
writedata(uchar *buf, int nbuf)
{
	DigestState *ds;
	uchar sha[SHA2_256dlen];

	while(recv(writes, &ds) < 0)
		yield();

	sha2_256(nil, 0, sha, ds);

	nbuf = nbuf >= SHA2_256dlen ? SHA2_256dlen : nbuf;
	memcpy(buf, sha, nbuf);
	return nbuf;
}

typedef struct eproc eproc;
struct eproc {
	int src;
	int sleepms;
	int isproc;
	char *name;
	int (*entropy)(uchar *buf, int nbuf);
};

static eproc sources[] = {
	{1,	5003,	1, "/dev/random",	truerandom},
	{2,	3001,	1, "#c/sysstat",	contextswitches},
	{3,	1009,	1, "#c/time",		nanoseconds},
	{4,	0,	0, "/srv/random",	writedata},
};

static void
entropyproc(void *v)
{
	int pool, n;
	uchar buf[32];
	eproc *e;

	pool = 0;
	e = v;

	threadsetname("%s", e->name);

	for(;!exiting;){
		n = e->entropy(buf, sizeof(buf));
		if(n > 0){
			if(debug) fprint(2, "src %d %s pool %d -> %d %.*H\n", e->src, e->name, pool, n, n, buf);
			faddentropy(fortuna, e->src, pool, buf, n);
			pool = (pool + 1) % FPOOLCOUNT;
		}
		sleep(e->sleepms);
	}

	adec(&nproc);
}

static void
procs(void)
{
	int i;

	for(i = 0; i < nelem(sources); i++){
		ainc(&nproc);
		if(sources[i].isproc)
			proccreate(entropyproc, &sources[i], 8192);
		else
			threadcreate(entropyproc, &sources[i], 8192);
	}
}

static void
seed(void)
{
	int n;
	uchar buf[32];

	n = truerandom(buf, sizeof(buf));
	assert(n == 32);
	faddentropy(fortuna, 0, 0, buf, sizeof(buf));
	n = nanoseconds(buf, sizeof(buf));
	assert(n == 32);
	faddentropy(fortuna, 0, 0, buf, sizeof(buf));
}


static int
fillstat(ulong qid, Dir *d)
{
	memset(d, 0, sizeof(Dir));

	d->uid = "rngd";
	d->gid = "rngd";
	d->muid = "";
	d->qid = (Qid){qid, 0, 0};
	d->atime = time(0);

	switch(qid) {
	case Qroot:
		d->name = "/";
		d->qid.type = QTDIR;
		d->mode = DMDIR|0777;
		break;
	case Qrandom:
		d->name = "random";
		d->mode = 0666;
		break;
	}
	return 1;
}

static int
readtopdir(Fid*, uchar *buf, long off, int cnt, int blen)
{
	int i, m, n;
	long pos;
	Dir d;

	n = 0;
	pos = 0;
	for (i = 1; i < Nqid; i++){
		fillstat(i, &d);
		m = convD2M(&d, &buf[n], blen-n);
		if(off <= pos){
			if(m <= BIT16SZ || m > cnt)
				break;
			n += m;
			cnt -= m;
		}
		pos += m;
	}
	return n;
}

static void
fsattach(Req *r)
{
	char *spec;

	spec = r->ifcall.aname;
	if(spec && spec[0]) {
		respond(r, "invalid attach specifier");
		return;
	}

	r->fid->qid = (Qid){Qroot, 0, QTDIR};
	r->ofcall.qid = r->fid->qid;
	respond(r, nil);
}

static void
fsstat(Req *r)
{
	fillstat((ulong)r->fid->qid.path, &r->d);

	r->d.name = estrdup9p(r->d.name);
	r->d.uid = estrdup9p(r->d.uid);
	r->d.gid = estrdup9p(r->d.gid);
	r->d.muid = estrdup9p(r->d.muid);

	respond(r, nil);
}

static char*
fswalk1(Fid *fid, char *name, Qid *qid)
{
	switch((ulong)fid->qid.path) {
	case Qroot:
		if (strcmp(name, "..") == 0) {
			*qid = (Qid){Qroot, 0, QTDIR};
			fid->qid = *qid;
			return nil;
		}
		if (strcmp(name, "random") == 0) {
			*qid = (Qid){Qrandom, 0, 0};
			fid->qid = *qid;
			return nil;
		}
		return "file not found";
		
	default:
		return "walk in non-directory";
	}
}

static void
fsopen(Req *r)
{
	int omode;
	Fid *fid;
	ulong path;

	fid = r->fid;
	path = (ulong)fid->qid.path;
	omode = r->ifcall.mode;
	
	if(path == Qroot){
		if (omode == OREAD)
			respond(r, nil);
		else
			respond(r, "permission denied");
		return;
	}
	respond(r, nil);
}

static void
fsread(Req *r)
{
	switch((ulong)r->fid->qid.path) {
	case Qroot:
		r->ofcall.count = readtopdir(r->fid, (void*)r->ofcall.data, r->ifcall.offset,
			r->ifcall.count, r->ifcall.count);
		respond(r, nil);
		return;

	case Qrandom:
		frandom(fortuna, (uchar*)r->ofcall.data, r->ifcall.count);
		r->ofcall.count = r->ifcall.count;
		respond(r, nil);
		return;
	}

	respond(r, "fixme");
}

static void
fswrite(Req *r)
{
	switch((ulong)r->fid->qid.path) {
	case Qrandom:
		sendp(writes, sha2_256((uchar*)r->ifcall.data, r->ifcall.count, nil, nil));
		r->ofcall.count = r->ifcall.count;
		respond(r, nil);
		return;
	}
	respond(r, "fixme");
}



static void
fsstart(Srv *)
{
	writes = chancreate(sizeof(DigestState*), 10);
	if(writes == nil)
		sysfatal("chancreate: %r");
	fortuna = newfortuna(nsec);
	if(fortuna == nil)
		sysfatal("newfortuna: %r");

	seed();
	procs();
}

static void
fsend(Srv *)
{
	ainc(&exiting);
	while(nproc != 0){
		yield();
		sleep(0);
	}

	fclose(fortuna);
}

static Srv fs = {
	.attach=		fsattach,
	.walk1=			fswalk1,
	.open=			fsopen,
	.read=			fsread,
	.write=			fswrite,
	.stat=			fsstat,
	.start=			fsstart,
	.end=			fsend,
};

void
usage(void)
{
	fprint(2, "usage: %s [-D]\n", argv0);
	threadexitsall("usage");
}

void
threadmain(int argc, char **argv)
{
	fmtinstall('H', encodefmt);

	ARGBEGIN{
	case 'D':
		if(debug > 0)
			chatty9p++;
		debug++;
		break;
	default:
		usage();
	}ARGEND;

	threadpostmountsrv(&fs, "random", "/dev", MBEFORE);
	threadexits(nil);
}

