typedef struct Fortuna Fortuna;
typedef struct Generator Generator;
typedef struct EPool EPool;
typedef int (*ESource)(uchar *buf, int *nbuf);

enum {
	FPOOLCOUNT	= 32,
	FPOOLMINSIZE	= 64,
};

struct Fortuna {
	QLock;
	vlong (*ns)(void);
	vlong lastseed;
	u64int nseed;
	uchar newseed[FPOOLCOUNT*SHA2_256dlen];
	Generator *g;
	EPool *pools[FPOOLCOUNT];
};

Fortuna *newfortuna(vlong (*ns)(void));
void frandom(Fortuna *f, uchar *buf, int nbuf);
void faddentropy(Fortuna *f, u8int src, u8int pool, uchar *buf, u8int nbuf);
void faddsource(Fortuna *f);
void fclose(Fortuna *f);

struct Generator {
	uchar key[SHA2_256dlen];
	uchar ctr[AESbsize];
};

Generator *newgenerator(void);
void greseed(Generator *g, uchar *seed, int nseed);
void grandom(Generator *g, uchar *buf, int nbuf);
void gclose(Generator *g);

// entropy pool
struct EPool {
	DigestState;
	u64int size;
};

EPool *newepool(void);
void epadd(EPool *p, uchar *buf, int nbuf);
u64int eplen(EPool *p);
void epsum(EPool *p, uchar *buf);

