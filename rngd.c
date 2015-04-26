#include <u.h>
#include <libc.h>
#include <auth.h>
#include <mp.h>
#include <libsec.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>

#include "fortuna.h"

static Fortuna *fortuna;

enum 
{
	Qroot,
	Qrandom,
	Nqid,
};

int
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

int
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
		respond(r, "not implemented");
		return;
	}
	respond(r, "fixme");
}

Srv fs = {
	.attach=		fsattach,
	.walk1=			fswalk1,
	.open=			fsopen,
	.read=			fsread,
	.write=			fswrite,
	.stat=			fsstat,
};

void
rndthread(void *)
{
	int pool;
	union {
		u32int i;
		uchar b[4];
	} u;

	pool = 0;

	for(;;){
		u.i = truerand();
		fprint(2, "rndthread: %.*H\n", sizeof(u.b), u.b);
		faddentropy(fortuna, 0, pool, u.b, sizeof(u.b));
		sleep(250);
	}
}

void
threadmain(int, char**)
{
	fmtinstall('H', encodefmt);

	fortuna = newfortuna();
	proccreate(rndthread, nil, 8192);
	threadpostmountsrv(&fs, "random", "/dev", MBEFORE);
}
