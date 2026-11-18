// mmr.c — in-kernel address-space reader, built into the image.
//
// Capability equivalent to /proc/<pid>/mem, except the page tables are walked by
// hand so a PROT_WRITE-only VMA does not block the read.
//
//   write()  struct mmr_req          configure the next operation
//   read()   up to req.len bytes     single read from req.va
//   ioctl    MMR_IOC_BATCH           scatter-gather over an array of segments
//            MMR_IOC_PHYS            read by physical address
//            MMR_IOC_TOKEN            claim the per-boot token, once
//   mmap()   window over req.va      zero-syscall reads after setup
//
// Defences: per-boot random token claimable once; uid + CAP_SYS_ADMIN gate;
// read-only; proc entry unlinked from the directory tree; symbol names chosen to
// blend into existing mm naming.
//
// Platform: Linux 6.1 GKI aarch64, PGTABLE_LEVELS=3, VA_BITS=39, 4 KiB pages,
// THP and swap on. The pgd->p4d->pud->pmd->pte chain folds on a 3-level kernel.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/highmem.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>


#define MMR_OP_READ   1
#define MMR_OP_MAP    5

#define MMR_MAX_LEN   (256u * 1024u)
#define MMR_MAX_SEGS  1024
#define MMR_UID       0u

struct mmr_req {
	u32 op;
	u32 token;
	s32 pid;
	u32 len;
	u64 va;
	u64 aux;
	u32 count;
	u32 _pad;
};

struct mmr_seg {
	u64 va;
	u32 len;
	u32 _pad;
};

#define MMR_IOC_BATCH _IOW('m', 1, struct mmr_req)
#define MMR_IOC_PHYS  _IOW('m', 2, struct mmr_req)
#define MMR_IOC_TOKEN _IO('m', 3)

#ifndef MODULE
struct proc_dir_entry;
/* Lives in fs/proc/generic.c, where the subdir lock is file-static. */
extern void proc_unlink_tree_entry(struct proc_dir_entry *de);
#endif

static struct proc_dir_entry *pid_mem_pde;
static char pid_mem_name[16];
static u32 mmr_token;
static bool mmr_claimed;

/* Single entry cache. No reference is retained between calls: the cached page is
 * revalidated with get_page_unless_zero, so a reclaimed page is re-walked rather
 * than dereferenced. */
static struct {
	struct page *page;
	unsigned long key;
} mmr_cache;

static DEFINE_MUTEX(mmr_lock);

// ---------------------------------------------------------------------------
// page resolution
// ---------------------------------------------------------------------------

static int mmr_page(struct mm_struct *mm, unsigned long va,
		    struct page **out, unsigned long *off)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	unsigned long pfn, idx = 0;
	struct page *page;
	const unsigned long key = va >> PAGE_SHIFT;

	if (mmr_cache.page && mmr_cache.key == key &&
	    get_page_unless_zero(mmr_cache.page)) {
		*out = mmr_cache.page;
		*off = va & ~PAGE_MASK;
		return 0;
	}

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -EFAULT;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -EFAULT;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud))
		return -EFAULT;

	if (pud_leaf(*pud)) {
		pfn = pud_pfn(*pud);
		idx = (va & (PUD_SIZE - 1)) >> PAGE_SHIFT;
		goto have_pfn;
	}

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return -EFAULT;
	if (pmd_leaf(*pmd)) {
		pfn = pmd_pfn(*pmd);
		idx = (va & (PMD_SIZE - 1)) >> PAGE_SHIFT;
		goto have_pfn;
	}

	ptep = pte_offset_map(pmd, va);
	if (!ptep)
		return -ENOMEM;
	pte = ptep_get(ptep);
	if (!pte_present(pte)) {
		pte_unmap(ptep);
		return -EAGAIN;
	}
	pfn = pte_pfn(pte);
	pte_unmap(ptep);

have_pfn:
	if (!pfn_valid(pfn + idx))
		return -EFAULT;
	page = pfn_to_page(pfn + idx);
	if (!get_page_unless_zero(page))
		return -EFAULT;

	mmr_cache.page = page;
	mmr_cache.key = key;
	*out = page;
	*off = va & ~PAGE_MASK;
	return 0;
}

static int mmr_fault_in(struct mm_struct *mm, unsigned long va)
{
	struct vm_area_struct *vma;
	vm_fault_t ret;
	int err = -EFAULT;

	mmap_read_lock(mm);
	vma = find_vma(mm, va);
	if (vma && vma->vm_start <= va) {
		ret = handle_mm_fault(vma, va, FAULT_FLAG_REMOTE, NULL);
		if (!(ret & VM_FAULT_ERROR))
			err = 0;
	}
	mmap_read_unlock(mm);
	return err;
}

static long mmr_read_range(struct mm_struct *mm, unsigned long va,
			   char __user *dst, u32 len)
{
	u32 done = 0;

	while (done < len) {
		unsigned long cur = va + done, off = 0;
		struct page *page = NULL;
		size_t chunk;
		void *base;
		int tries, ret = -EFAULT;

		for (tries = 0; tries < 2; tries++) {
			mmap_read_lock(mm);
			ret = mmr_page(mm, cur, &page, &off);
			mmap_read_unlock(mm);
			if (ret == 0)
				break;
			if (ret != -EAGAIN)
				return ret;
			if (mmr_fault_in(mm, cur) != 0)
				return -EFAULT;
		}
		if (ret != 0)
			return -EFAULT;

		chunk = len - done;
		if (chunk > PAGE_SIZE - off)
			chunk = PAGE_SIZE - off;

		base = kmap_local_page(page);
		if (copy_to_user(dst + done, (char *)base + off, chunk))
			ret = -EFAULT;
		kunmap_local(base);
		put_page(page);
		if (ret != 0)
			return ret;
		done += chunk;
	}
	return done;
}

static int mmr_task(int pid, struct mm_struct **mm_out)
{
	struct pid *p;
	struct task_struct *t;
	struct mm_struct *mm;

	p = find_get_pid(pid);
	if (!p)
		return -ESRCH;
	t = get_pid_task(p, PIDTYPE_PID);
	put_pid(p);
	if (!t)
		return -ESRCH;
	mm = get_task_mm(t);
	put_task_struct(t);
	if (!mm)
		return -EINVAL;
	*mm_out = mm;
	return 0;
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

static long mmr_do_read(struct mmr_req *r, char __user *dst, u32 len)
{
	struct mm_struct *mm;
	long ret;

	if (mmr_task(r->pid, &mm))
		return -ESRCH;
	ret = mmr_read_range(mm, (unsigned long)r->va, dst, len);
	mmput(mm);
	return ret;
}

static long mmr_do_batch(struct mmr_req *r)
{
	struct mmr_seg *segs;
	struct mm_struct *mm;
	char __user *out;
	long ret = 0;
	u32 i;

	if (r->count == 0 || r->count > MMR_MAX_SEGS)
		return -EINVAL;
	segs = kcalloc(r->count, sizeof(*segs), GFP_KERNEL);
	if (!segs)
		return -ENOMEM;
	if (copy_from_user(segs, (void __user *)r->aux,
			   r->count * sizeof(*segs))) {
		kfree(segs);
		return -EFAULT;
	}
	if (mmr_task(r->pid, &mm)) {
		kfree(segs);
		return -ESRCH;
	}
	out = (char __user *)r->va;      /* destination buffer */
	for (i = 0; i < r->count; ++i) {
		long n = mmr_read_range(mm, (unsigned long)segs[i].va, out,
					segs[i].len);
		if (n < 0) {
			ret = n;
			break;
		}
		out += n;
		ret += n;
	}
	mmput(mm);
	kfree(segs);
	return ret;
}

static long mmr_do_phys(struct mmr_req *r, char __user *dst)
{
	unsigned long addr = (unsigned long)r->aux;
	unsigned long pfn = addr >> PAGE_SHIFT;
	unsigned long off = addr & ~PAGE_MASK;
	u32 len = r->len, done = 0;
	struct page *page;
	void *base;

	if (!pfn_valid(pfn))
		return -EFAULT;
	page = pfn_to_page(pfn);
	if (!get_page_unless_zero(page))
		return -EFAULT;

	while (done < len) {
		size_t chunk = len - done;
		if (chunk > PAGE_SIZE - off)
			chunk = PAGE_SIZE - off;
		base = kmap_local_page(page);
		if (copy_to_user(dst + done, (char *)base + off, chunk)) {
			kunmap_local(base);
			put_page(page);
			return -EFAULT;
		}
		kunmap_local(base);
		done += chunk;
		off = 0;
		if (done < len) {
			put_page(page);
			if (!pfn_valid(++pfn))
				break;
			page = pfn_to_page(pfn);
			if (!get_page_unless_zero(page))
				break;
		}
	}
	put_page(page);
	return done;
}

// ---------------------------------------------------------------------------
// mmap: map a target range into the caller's address space
// ---------------------------------------------------------------------------

struct mmr_vma {
	s32 pid;
	u64 va;
	u32 len;
};

static void mmr_vma_open(struct vm_area_struct *vma)
{
}

static void mmr_vma_close(struct vm_area_struct *vma)
{
	kfree(vma->vm_private_data);
	vma->vm_private_data = NULL;
}

static vm_fault_t mmr_vma_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mmr_vma *ctx = vma->vm_private_data;
	unsigned long va, off;
	struct mm_struct *mm;
	struct page *page = NULL;
	vm_fault_t ret = VM_FAULT_SIGBUS;
	int err;

	if (!ctx)
		return VM_FAULT_SIGBUS;
	va = (unsigned long)ctx->va + (vmf->address - vma->vm_start);

	if (mmr_task(ctx->pid, &mm))
		return VM_FAULT_SIGBUS;

	mmap_read_lock(mm);
	err = mmr_page(mm, va, &page, &off);
	mmap_read_unlock(mm);
	if (err == -EAGAIN) {
		mmr_fault_in(mm, va);
		mmap_read_lock(mm);
		err = mmr_page(mm, va, &page, &off);
		mmap_read_unlock(mm);
	}
	mmput(mm);
	if (err)
		return VM_FAULT_SIGBUS;

	if (vm_insert_page(vma, vmf->address, page) == 0)
		ret = VM_FAULT_NOPAGE;
	put_page(page);
	return ret;
}

static const struct vm_operations_struct mmr_vm_ops = {
	.open  = mmr_vma_open,
	.close = mmr_vma_close,
	.fault = mmr_vma_fault,
};

static int mmr_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mmr_req *r = file->private_data;
	struct mmr_vma *ctx;
	unsigned long size = vma->vm_end - vma->vm_start;

	if (!r || r->op != MMR_OP_MAP || r->len == 0 || r->token != mmr_token)
		return -EINVAL;
	if (size > r->len)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->pid = r->pid;
	ctx->va = r->va;
	ctx->len = r->len;

	vma->vm_ops = &mmr_vm_ops;
	vma->vm_private_data = ctx;
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	return 0;
}

// ---------------------------------------------------------------------------
// file operations
// ---------------------------------------------------------------------------

static bool mmr_allowed(void)
{
	return capable(CAP_SYS_ADMIN) &&
	       uid_eq(current_fsuid(), KUIDT_INIT(MMR_UID));
}

static ssize_t pid_mem_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct mmr_req *r = file->private_data;

	if (count != sizeof(*r))
		return -EINVAL;
	if (!mmr_allowed())
		return -EPERM;
	if (copy_from_user(r, ubuf, sizeof(*r)))
		return -EFAULT;
	if (r->token != mmr_token)
		return -EACCES;
	if (r->len > MMR_MAX_LEN)
		return -EINVAL;
	return count;
}

static ssize_t pid_mem_read(struct file *file, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct mmr_req *r = file->private_data;
	u32 want;

	if (!r || r->token != mmr_token)
		return -EACCES;
	if (!mmr_allowed())
		return -EPERM;
	if (r->op != MMR_OP_READ)
		return -EINVAL;

	want = min_t(u32, (u32)count, r->len);
	if (!want)
		return 0;
	return mmr_do_read(r, ubuf, want);
}

static long pid_mem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct mmr_req tmp;

	if (!mmr_allowed())
		return -EPERM;

	switch (cmd) {
	case MMR_IOC_TOKEN: {
		u32 out;

		mutex_lock(&mmr_lock);
		if (mmr_claimed) {
			mutex_unlock(&mmr_lock);
			return -EALREADY;
		}
		mmr_claimed = true;
		out = mmr_token;
		mutex_unlock(&mmr_lock);
		if (copy_to_user((void __user *)arg, &out, sizeof(out)))
			return -EFAULT;
		return 0;
	}
	case MMR_IOC_BATCH:
		if (copy_from_user(&tmp, (void __user *)arg, sizeof(tmp)))
			return -EFAULT;
		if (tmp.token != mmr_token)
			return -EACCES;
		return mmr_do_batch(&tmp);
	case MMR_IOC_PHYS: {
		char __user *dst;

		if (copy_from_user(&tmp, (void __user *)arg, sizeof(tmp)))
			return -EFAULT;
		if (tmp.token != mmr_token)
			return -EACCES;
		dst = (char __user *)tmp.va;
		return mmr_do_phys(&tmp, dst);
	}
	default:
		return -ENOTTY;
	}
}

static int pid_mem_open(struct inode *inode, struct file *file)
{
	struct mmr_req *r = kzalloc(sizeof(*r), GFP_KERNEL);

	if (!r)
		return -ENOMEM;
	file->private_data = r;
	return 0;
}

static int pid_mem_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct proc_ops pid_mem_ops = {
	.proc_open    = pid_mem_open,
	.proc_read    = pid_mem_read,
	.proc_write   = pid_mem_write,
	.proc_ioctl   = pid_mem_ioctl,
	.proc_mmap    = mmr_mmap,
	.proc_release = pid_mem_release,
};

// ---------------------------------------------------------------------------
// hiding and init
// ---------------------------------------------------------------------------

static int __init mm_reader_init(void)
{
	u32 rnd;

	get_random_bytes(&rnd, sizeof(rnd));
	mmr_token = rnd | 1;

	snprintf(pid_mem_name, sizeof(pid_mem_name), "%06x",
		 (unsigned int)(rnd >> 8) & 0xffffff);

	pid_mem_pde = proc_create(pid_mem_name, 0600, NULL, &pid_mem_ops);
	if (!pid_mem_pde)
		return -ENOMEM;
#ifndef MODULE
	proc_unlink_tree_entry(pid_mem_pde);
#endif
	return 0;
}

module_init(mm_reader_init);
MODULE_LICENSE("GPL");
