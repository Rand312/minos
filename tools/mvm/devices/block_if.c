/*-
 * Copyright (c) 2013  Peter Grehan <grehan@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>

#include <minos/block_if.h>
#include <minos/ahci.h>

#define MAXCOMLEN	19

/*
 * Notes:
 * The F_OFD_SETLK support is introduced in glibc 2.20.
 * The glibc version on target board is above 2.20.
 * The following code temporarily fixes up building issues on Ubuntu 14.04,
 * where the glibc version is 2.19 by default.
 * Theoretically we should use cross-compiling tool to compile applications.
 */
#ifndef F_OFD_SETLK
#define F_OFD_SETLK	37
#endif

#define BLOCKIF_SIG	0xb109b109

#define BLOCKIF_NUMTHR	8
#define BLOCKIF_MAXREQ	(64 + BLOCKIF_NUMTHR)

/*
 * Debug printf
 */
static int block_if_debug;
#define DPRINTF(params) do { if (block_if_debug) printf params; } while (0)
#define WPRINTF(params) (printf params)

enum blockop {
	BOP_READ,
	BOP_WRITE,
	BOP_FLUSH,
	BOP_DELETE
};

enum blockstat {
	BST_FREE,
	BST_BLOCK,
	BST_PEND,
	BST_BUSY,
	BST_DONE
};

struct blockif_elem {
	TAILQ_ENTRY(blockif_elem) link;
	struct blockif_req  *req;
	enum blockop	     op;
	enum blockstat	     status;
	pthread_t            tid;
	off_t		     block;
};

struct blockif_ctxt {
	int			magic;
	int			fd;
	int			isblk;
	int			isgeom;
	int			candelete;
	int			rdonly;
	off_t			size;
	int			sub_file_assign;
	off_t			sub_file_start_lba;
	struct flock		fl;
	int			sectsz;
	int			psectsz;
	int			psectoff;
	int			closing;
	pthread_t		btid[BLOCKIF_NUMTHR];
	pthread_mutex_t		mtx;
	pthread_cond_t		cond;

	/* Request elements and free/pending/busy queues */
	TAILQ_HEAD(, blockif_elem) freeq;
	TAILQ_HEAD(, blockif_elem) pendq;
	TAILQ_HEAD(, blockif_elem) busyq;
	struct blockif_elem	reqs[BLOCKIF_MAXREQ];

	/* write cache enable */
	uint8_t			wce;
};

static pthread_once_t blockif_once = PTHREAD_ONCE_INIT;

struct blockif_sig_elem {
	pthread_mutex_t			mtx;
	pthread_cond_t			cond;
	int				pending;
	struct blockif_sig_elem		*next;
};

static struct blockif_sig_elem *blockif_bse_head;

static int
blockif_flush_cache(struct blockif_ctxt *bc)
{
	int err;

	err = 0;
	assert(bc != NULL);
	if (!bc->wce) {
		if (fsync(bc->fd))
			err = errno;
	}
	return err;
}

static int
blockif_enqueue(struct blockif_ctxt *bc, struct blockif_req *breq,
		enum blockop op)
{
	struct blockif_elem *be, *tbe;
	off_t off;
	int i;

	be = TAILQ_FIRST(&bc->freeq);
	assert(be != NULL);
	assert(be->status == BST_FREE);
	TAILQ_REMOVE(&bc->freeq, be, link);
	be->req = breq;
	be->op = op;
	switch (op) {
	case BOP_READ:
	case BOP_WRITE:
	case BOP_DELETE:
		off = breq->offset;
		for (i = 0; i < breq->iovcnt; i++)
			off += breq->iov[i].iov_len;
		break;
	default:
		/* off = OFF_MAX; */
		off = 1 << (sizeof(off_t) - 1);
	}
	be->block = off;
	TAILQ_FOREACH(tbe, &bc->pendq, link) {
		if (tbe->block == breq->offset)
			break;
	}
	if (tbe == NULL) {
		TAILQ_FOREACH(tbe, &bc->busyq, link) {
			if (tbe->block == breq->offset)
				break;
		}
	}
	if (tbe == NULL)
		be->status = BST_PEND;
	else
		be->status = BST_BLOCK;
	TAILQ_INSERT_TAIL(&bc->pendq, be, link);
	return (be->status == BST_PEND);
}

static int
blockif_dequeue(struct blockif_ctxt *bc, pthread_t t, struct blockif_elem **bep)
{
	struct blockif_elem *be;

	TAILQ_FOREACH(be, &bc->pendq, link) {
		if (be->status == BST_PEND)
			break;
		assert(be->status == BST_BLOCK);
	}
	if (be == NULL)
		return 0;
	TAILQ_REMOVE(&bc->pendq, be, link);
	be->status = BST_BUSY;
	be->tid = t;
	TAILQ_INSERT_TAIL(&bc->busyq, be, link);
	*bep = be;
	return 1;
}

static void
blockif_complete(struct blockif_ctxt *bc, struct blockif_elem *be)
{
	struct blockif_elem *tbe;

	if (be->status == BST_DONE || be->status == BST_BUSY)
		TAILQ_REMOVE(&bc->busyq, be, link);
	else
		TAILQ_REMOVE(&bc->pendq, be, link);
	TAILQ_FOREACH(tbe, &bc->pendq, link) {
		if (tbe->req->offset == be->block)
			tbe->status = BST_PEND;
	}
	be->tid = 0;
	be->status = BST_FREE;
	be->req = NULL;
	TAILQ_INSERT_TAIL(&bc->freeq, be, link);
}

static void
blockif_proc(struct blockif_ctxt *bc, struct blockif_elem *be, uint8_t *buf)
{
	struct blockif_req *br;
	off_t arg[2];
	ssize_t clen, len, off, boff, voff;
	int i, err;

	br = be->req;
	if (br->iovcnt <= 1)
		buf = NULL;
	err = 0;
	switch (be->op) {
	case BOP_READ:
		if (buf == NULL) {
			len = preadv(bc->fd, br->iov, br->iovcnt,
				     br->offset + bc->sub_file_start_lba);
			if (len < 0)
				err = errno;
			else
				br->resid -= len;
			break;
		}
		i = 0;
		off = voff = 0;
		while (br->resid > 0) {
			len = MIN(br->resid, MAXPHYS);
			if (pread(bc->fd, buf, len, br->offset +
			    off + bc->sub_file_start_lba) < 0) {
				err = errno;
				break;
			}
			boff = 0;
			do {
				clen = MIN(len - boff, br->iov[i].iov_len -
				    voff);
				memcpy(br->iov[i].iov_base + voff,
				    buf + boff, clen);
				if (clen < br->iov[i].iov_len - voff)
					voff += clen;
				else {
					i++;
					voff = 0;
				}
				boff += clen;
			} while (boff < len);
			off += len;
			br->resid -= len;
		}
		break;
	case BOP_WRITE:
		if (bc->rdonly) {
			err = EROFS;
			break;
		}
		if (buf == NULL) {
			len = pwritev(bc->fd, br->iov, br->iovcnt,
				      br->offset + bc->sub_file_start_lba);
			if (len < 0)
				err = errno;
			else {
				br->resid -= len;
				err = blockif_flush_cache(bc);
			}
			break;
		}
		i = 0;
		off = voff = 0;
		while (br->resid > 0) {
			len = MIN(br->resid, MAXPHYS);
			boff = 0;
			do {
				clen = MIN(len - boff, br->iov[i].iov_len -
				    voff);
				memcpy(buf + boff,
				    br->iov[i].iov_base + voff, clen);
				if (clen < br->iov[i].iov_len - voff)
					voff += clen;
				else {
					i++;
					voff = 0;
				}
				boff += clen;
			} while (boff < len);
			if (pwrite(bc->fd, buf, len, br->offset +
			    off + bc->sub_file_start_lba) < 0) {
				err = errno;
				break;
			}
			off += len;
			br->resid -= len;
		}
		err = blockif_flush_cache(bc);

		break;
	case BOP_FLUSH:
		if (fsync(bc->fd))
			err = errno;
		break;
	case BOP_DELETE:
		/* only used by AHCI */
		if (!bc->candelete)
			err = EOPNOTSUPP;
		else if (bc->rdonly)
			err = EROFS;
		else if (bc->isblk) {
			arg[0] = br->offset;
			arg[1] = br->resid;
			if (ioctl(bc->fd, BLKDISCARD, arg))
				err = errno;
			else
				br->resid = 0;
		}
		else
			err = EOPNOTSUPP;
		break;
	default:
		err = EINVAL;
		break;
	}

	be->status = BST_DONE;

	(*br->callback)(br, err);
}

static void *
blockif_thr(void *arg)
{
	struct blockif_ctxt *bc;
	struct blockif_elem *be;
	pthread_t t;
	uint8_t *buf;

	bc = arg;
	if (bc->isgeom)
		buf = malloc(MAXPHYS);
	else
		buf = NULL;
	t = pthread_self();

	pthread_mutex_lock(&bc->mtx);
	for (;;) {
		while (blockif_dequeue(bc, t, &be)) {
			pthread_mutex_unlock(&bc->mtx);
			blockif_proc(bc, be, buf);
			pthread_mutex_lock(&bc->mtx);
			blockif_complete(bc, be);
		}
		/* Check ctxt status here to see if exit requested */
		if (bc->closing)
			break;
		pthread_cond_wait(&bc->cond, &bc->mtx);
	}
	pthread_mutex_unlock(&bc->mtx);

	if (buf)
		free(buf);
	pthread_exit(NULL);
	return NULL;
}

static void
blockif_sigcont_handler(int signal)
{
	struct blockif_sig_elem *bse;

	WPRINTF(("block_if sigcont handler!\n"));

	for (;;) {
		/*
		 * Process the entire list even if not intended for
		 * this thread.
		 */
		do {
			bse = blockif_bse_head;
			if (bse == NULL)
				return;
		} while (!__sync_bool_compare_and_swap(
					(uintptr_t *)&blockif_bse_head,
					(uintptr_t)bse,
					(uintptr_t)bse->next));

		pthread_mutex_lock(&bse->mtx);
		bse->pending = 0;
		pthread_cond_signal(&bse->cond);
		pthread_mutex_unlock(&bse->mtx);
	}
}

static void
blockif_init(void)
{
	signal(SIGCONT, blockif_sigcont_handler);
}

/*
 * This function checks if the sub file range, specified by sub_start and
 * sub_size, has any overlap with other sub file ranges with write access.
 */
static int
sub_file_validate(struct blockif_ctxt *bc, int fd, int read_only,
		  off_t sub_start, off_t sub_size)
{
	struct flock *fl = &bc->fl;

	memset(fl, 0, sizeof(struct flock));
	fl->l_whence = SEEK_SET;	/* offset base is start of file */
	if (read_only)
		fl->l_type = F_RDLCK;
	else
		fl->l_type = F_WRLCK;
	fl->l_start = sub_start;
	fl->l_len = sub_size;

	/* use "open file description locks" to validate */
	if (fcntl(fd, F_OFD_SETLK, fl) == -1) {
		DPRINTF(("failed to lock subfile!\n"));
		return -1;
	}

	/* Keep file lock on to prevent other sub files, until DM exits */
	return 0;
}

void
sub_file_unlock(struct blockif_ctxt *bc)
{
	struct flock *fl;

	if (bc->sub_file_assign) {
		fl = &bc->fl;
		DPRINTF(("blockif: release file lock...\n"));
		fl->l_type = F_UNLCK;
		if (fcntl(bc->fd, F_OFD_SETLK, fl) == -1) {
			fprintf(stderr, "blockif: failed to unlock subfile!\n");
			exit(1);
		}
		DPRINTF(("blockif: release done\n"));
	}
}


struct blockif_ctxt *
blockif_open(const char *optstr, const char *ident)
{
	char tname[MAXCOMLEN + 1];
	/* char name[MAXPATHLEN]; */
	char *nopt, *xopts, *cp;
	struct blockif_ctxt *bc;
	struct stat sbuf;
	/* struct diocgattr_arg arg; */
	off_t size, psectsz, psectoff;
	int fd, i, sectsz;
	int writeback, ro, candelete, geom, ssopt, pssopt;
	long sz;
	long long b;
	int err_code = -1;
	off_t sub_file_start_lba, sub_file_size;
	int sub_file_assign;

	// 多线程情况下，blockif_open() 只被调用一次
	pthread_once(&blockif_once, blockif_init);

	fd = -1;
	ssopt = 0;
	ro = 0;
	sub_file_assign = 0;

	/* writethru is on by default */
	writeback = 0;

	/*
	 * The first element in the optstring is always a pathname.
	 * Optional elements follow
	 */
	nopt = xopts = strdup(optstr);
	if (!nopt) {
		WPRINTF(("block_if.c: strdup retruns NULL\n"));
		return NULL;
	}
	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt)		/* file or device pathname */
			continue;
		else if (!strcmp(cp, "writeback"))
			writeback = 1;
		else if (!strcmp(cp, "writethru"))
			writeback = 0;
		else if (!strcmp(cp, "ro"))
			ro = 1;
		else if (sscanf(cp, "sectorsize=%d/%d", &ssopt, &pssopt) == 2)
			;
		else if (sscanf(cp, "sectorsize=%d", &ssopt) == 1)
			pssopt = ssopt;
		else if (sscanf(cp, "range=%ld/%ld", &sub_file_start_lba,
				&sub_file_size) == 2)
			sub_file_assign = 1;
		else {
			fprintf(stderr, "Invalid device option \"%s\"\n", cp);
			goto err;
		}
	}

	/*
	 * To support "writeback" and "writethru" mode switch during runtime,
	 * O_SYNC is not used directly, as O_SYNC flag cannot dynamic change
	 * after file is opened. Instead, we call fsync() after each write
	 * operation to emulate it.
	 */

	fd = open(nopt, ro ? O_RDONLY : O_RDWR);
	if (fd < 0 && !ro) {
		/* Attempt a r/w fail with a r/o open */
		fd = open(nopt, O_RDONLY);
		ro = 1;
	}

	if (fd < 0) {
		warn("Could not open backing file: %s", nopt);
		goto err;
	}

	if (fstat(fd, &sbuf) < 0) {
		warn("Could not stat backing file %s", nopt);
		goto err;
	}

	/*
	 * Deal with raw devices
	 */
	size = sbuf.st_size;
	sectsz = DEV_BSIZE;
	psectsz = psectoff = 0;
	candelete = geom = 0;

	if (S_ISBLK(sbuf.st_mode)) {
		/* get size */
		err_code = ioctl(fd, BLKGETSIZE, &sz);
		if (err_code) {
			fprintf(stderr, "error %d getting block size!\n",
				err_code);
			size = sbuf.st_size;	/* set default value */
		} else {
			size = sz * DEV_BSIZE;	/* DEV_BSIZE is 512 on Linux */
		}
		if (!err_code || err_code == EFBIG) {
			err_code = ioctl(fd, BLKGETSIZE64, &b);
			if (err_code || b == 0 || b == sz)
				size = b * DEV_BSIZE;
			else
				size = b;
		}
		DPRINTF(("block partition size is 0x%lx\n", size));

		/* get sector size, 512 on Linux */
		sectsz = DEV_BSIZE;
		DPRINTF(("block partition sector size is 0x%x\n", sectsz));

		/* get physical sector size */
		err_code = ioctl(fd, BLKPBSZGET, &psectsz);
		if (err_code) {
			fprintf(stderr, "error %d getting physical sectsz!\n",
				err_code);
			psectsz = DEV_BSIZE;  /* set default physical size */
		}
		DPRINTF(("block partition physical sector size is 0x%lx\n",
			 psectsz));

	} else
		psectsz = sbuf.st_blksize;

	if (ssopt != 0) {
		if (!powerof2(ssopt) || !powerof2(pssopt) || ssopt < 512 ||
		    ssopt > pssopt) {
			fprintf(stderr, "Invalid sector size %d/%d\n",
			    ssopt, pssopt);
			goto err;
		}

		/*
		 * Some backend drivers (e.g. cd0, ada0) require that the I/O
		 * size be a multiple of the device's sector size.
		 *
		 * Validate that the emulated sector size complies with this
		 * requirement.
		 */
		if (S_ISCHR(sbuf.st_mode)) {
			if (ssopt < sectsz || (ssopt % sectsz) != 0) {
				fprintf(stderr,
				"Sector size %d incompatible with underlying device sector size %d\n",
				    ssopt, sectsz);
				goto err;
			}
		}

		sectsz = ssopt;
		psectsz = pssopt;
		psectoff = 0;
	}

	bc = calloc(1, sizeof(struct blockif_ctxt));
	if (bc == NULL) {
		perror("calloc");
		goto err;
	}

	if (sub_file_assign) {
		DPRINTF(("sector size is %d\n", sectsz));
		bc->sub_file_assign = 1;
		bc->sub_file_start_lba = sub_file_start_lba * sectsz;
		size = sub_file_size * sectsz;
		DPRINTF(("Validating sub file...\n"));
		err_code = sub_file_validate(bc, fd, ro, bc->sub_file_start_lba,
					     size);
		if (err_code < 0) {
			fprintf(stderr, "subfile range specified not valid!\n");
			exit(1);
		}
		DPRINTF(("Validated done!\n"));
	} else {
		/* normal case */
		bc->sub_file_assign = 0;
		bc->sub_file_start_lba = 0;
	}

	bc->magic = BLOCKIF_SIG;
	bc->fd = fd;
	bc->isblk = S_ISBLK(sbuf.st_mode);
	bc->isgeom = geom;
	bc->candelete = candelete;
	bc->rdonly = ro;
	bc->size = size;
	bc->sectsz = sectsz;
	bc->psectsz = psectsz;
	bc->psectoff = psectoff;
	bc->wce = writeback;
	pthread_mutex_init(&bc->mtx, NULL);
	pthread_cond_init(&bc->cond, NULL);
	TAILQ_INIT(&bc->freeq);
	TAILQ_INIT(&bc->pendq);
	TAILQ_INIT(&bc->busyq);
	for (i = 0; i < BLOCKIF_MAXREQ; i++) {
		bc->reqs[i].status = BST_FREE;
		TAILQ_INSERT_HEAD(&bc->freeq, &bc->reqs[i], link);
	}

	for (i = 0; i < BLOCKIF_NUMTHR; i++) {
		pthread_create(&bc->btid[i], NULL, blockif_thr, bc);
		snprintf(tname, sizeof(tname), "blk-%s-%d", ident, i);
		pthread_setname_np(bc->btid[i], tname);
	}

	return bc;
err:
	if (fd >= 0)
		close(fd);
	return NULL;
}

static int
blockif_request(struct blockif_ctxt *bc, struct blockif_req *breq,
		enum blockop op)
{
	int err;

	err = 0;

	pthread_mutex_lock(&bc->mtx);
	if (!TAILQ_EMPTY(&bc->freeq)) {
		/*
		 * Enqueue and inform the block i/o thread
		 * that there is work available
		 */
		// enqueue 一个 node，然后通知 io thread 来干活儿
		if (blockif_enqueue(bc, breq, op))
			pthread_cond_signal(&bc->cond);
	} else {
		/*
		 * Callers are not allowed to enqueue more than
		 * the specified blockif queue limit. Return an
		 * error to indicate that the queue length has been
		 * exceeded.
		 */
		err = E2BIG;
	}
	pthread_mutex_unlock(&bc->mtx);

	return err;
}

int
blockif_read(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->magic == BLOCKIF_SIG);
	return blockif_request(bc, breq, BOP_READ);
}

int
blockif_write(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->magic == BLOCKIF_SIG);
	return blockif_request(bc, breq, BOP_WRITE);
}

int
blockif_flush(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->magic == BLOCKIF_SIG);
	return blockif_request(bc, breq, BOP_FLUSH);
}

int
blockif_delete(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->magic == BLOCKIF_SIG);
	return blockif_request(bc, breq, BOP_DELETE);
}

int
blockif_cancel(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	struct blockif_elem *be;

	assert(bc->magic == BLOCKIF_SIG);

	pthread_mutex_lock(&bc->mtx);
	/*
	 * Check pending requests.
	 */
	TAILQ_FOREACH(be, &bc->pendq, link) {
		if (be->req == breq)
			break;
	}
	if (be != NULL) {
		/*
		 * Found it.
		 */
		blockif_complete(bc, be);
		pthread_mutex_unlock(&bc->mtx);

		return 0;
	}

	/*
	 * Check in-flight requests.
	 */
	TAILQ_FOREACH(be, &bc->busyq, link) {
		if (be->req == breq)
			break;
	}
	if (be == NULL) {
		/*
		 * Didn't find it.
		 */
		pthread_mutex_unlock(&bc->mtx);
		return -1;
	}

	/*
	 * Interrupt the processing thread to force it return
	 * prematurely via it's normal callback path.
	 */
	while (be->status == BST_BUSY) {
		struct blockif_sig_elem bse, *old_head;

		pthread_mutex_init(&bse.mtx, NULL);
		pthread_cond_init(&bse.cond, NULL);

		bse.pending = 1;

		do {
			old_head = blockif_bse_head;
			bse.next = old_head;
		} while (!__sync_bool_compare_and_swap((uintptr_t *)&
							blockif_bse_head,
					    (uintptr_t)old_head,
					    (uintptr_t)&bse));

		pthread_kill(be->tid, SIGCONT);

		pthread_mutex_lock(&bse.mtx);
		while (bse.pending)
			pthread_cond_wait(&bse.cond, &bse.mtx);
		pthread_mutex_unlock(&bse.mtx);
	}

	pthread_mutex_unlock(&bc->mtx);

	/*
	 * The processing thread has been interrupted.  Since it's not
	 * clear if the callback has been invoked yet, return EBUSY.
	 */
	return -EBUSY;
}

int
blockif_close(struct blockif_ctxt *bc)
{
	void *jval;
	int i;

	assert(bc->magic == BLOCKIF_SIG);
	sub_file_unlock(bc);

	/*
	 * Stop the block i/o thread
	 */
	pthread_mutex_lock(&bc->mtx);
	bc->closing = 1;
	pthread_mutex_unlock(&bc->mtx);
	pthread_cond_broadcast(&bc->cond);
	for (i = 0; i < BLOCKIF_NUMTHR; i++)
		pthread_join(bc->btid[i], &jval);

	/* XXX Cancel queued i/o's ??? */

	/*
	 * Release resources
	 */
	bc->magic = 0;
	close(bc->fd);
	free(bc);

	return 0;
}

/*
 * Return virtual C/H/S values for a given block. Use the algorithm
 * outlined in the VHD specification to calculate values.
 */
void
blockif_chs(struct blockif_ctxt *bc, uint16_t *c, uint8_t *h, uint8_t *s)
{
	off_t sectors;		/* total sectors of the block dev */
	off_t hcyl;		/* cylinders times heads */
	uint16_t secpt;		/* sectors per track */
	uint8_t heads;

	assert(bc->magic == BLOCKIF_SIG);

	sectors = bc->size / bc->sectsz;

	/* Clamp the size to the largest possible with CHS */
	if (sectors > 65535UL*16*255)
		sectors = 65535UL*16*255;

	if (sectors >= 65536UL*16*63) {
		secpt = 255;
		heads = 16;
		hcyl = sectors / secpt;
	} else {
		secpt = 17;
		hcyl = sectors / secpt;
		heads = (hcyl + 1023) / 1024;

		if (heads < 4)
			heads = 4;

		if (hcyl >= (heads * 1024) || heads > 16) {
			secpt = 31;
			heads = 16;
			hcyl = sectors / secpt;
		}
		if (hcyl >= (heads * 1024)) {
			secpt = 63;
			heads = 16;
			hcyl = sectors / secpt;
		}
	}

	*c = hcyl / heads;
	*h = heads;
	*s = secpt;
}

/*
 * Accessors
 */
off_t
blockif_size(struct blockif_ctxt *bc)
{
	assert(bc->magic == BLOCKIF_SIG);
	return bc->size;
}

int
blockif_sectsz(struct blockif_ctxt *bc)
{
	assert(bc->magic == BLOCKIF_SIG);
	return bc->sectsz;
}

void
blockif_psectsz(struct blockif_ctxt *bc, int *size, int *off)
{
	assert(bc->magic == BLOCKIF_SIG);
	*size = bc->psectsz;
	*off = bc->psectoff;
}

int
blockif_queuesz(struct blockif_ctxt *bc)
{
	assert(bc->magic == BLOCKIF_SIG);
	return (BLOCKIF_MAXREQ - 1);
}

int
blockif_is_ro(struct blockif_ctxt *bc)
{
	assert(bc->magic == BLOCKIF_SIG);
	return bc->rdonly;
}

int
blockif_candelete(struct blockif_ctxt *bc)
{
	assert(bc->magic == BLOCKIF_SIG);
	return bc->candelete;
}

uint8_t
blockif_get_wce(struct blockif_ctxt *bc)
{
	assert(bc->magic == BLOCKIF_SIG);
	return bc->wce;
}

void
blockif_set_wce(struct blockif_ctxt *bc, uint8_t wce)
{
	assert(bc->magic == BLOCKIF_SIG);
	bc->wce = wce;
}

int
blockif_flush_all(struct blockif_ctxt *bc)
{
	int err;

	err=0;
	assert(bc->magic == BLOCKIF_SIG);
	if (fsync(bc->fd))
		err = errno;
	return err;
}
