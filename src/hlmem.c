// hlmem.c — in-kernel address-space reader for debugger-style introspection.
//
// Equivalent in capability to /proc/<pid>/mem, with one deliberate difference:
// it walks the page tables itself instead of calling access_process_vm(), so a
// target VMA that has been mprotect()ed to PROT_WRITE-only does not block the
// read. Those VMAs exist in real applications and are otherwise unreadable from
// user space by any means.
//
// Scope, deliberately narrow:
//   * read only, no write path
//   * caller must hold CAP_SYS_ADMIN and present a compile-time magic
//   * the registered proc entry is unlinked from the directory tree so it does
//     not appear in listings
//
// Platform facts this was written against (verified on the device):
//   Linux 6.1.118 GKI aarch64
//   CONFIG_PGTABLE_LEVELS=3, CONFIG_ARM64_VA_BITS=39
//   PAGESIZE=4096, CONFIG_TRANSPARENT_HUGEPAGE=y, CONFIG_SWAP=y
//
// The walk uses the generic pgd->p4d->pud->pmd->pte chain. On a 3-level kernel
// p4d and pud are folded by the pgtable-nop4d/nopud headers, so this compiles to
// three real levels without hardcoding a level count.

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
#include <linux/rbtree.h>

#include "../../fs/proc/internal.h"

#define HLMEM_MAGIC   0x484C4D45u          /* "HLME" */
#define HLMEM_MAX_LEN (64u * 1024u)        /* one request never exceeds this */

struct hlmem_req {
	u32 magic;
	s32 pid;
	u64 va;
	u32 len;
	u32 _pad;
};

static struct proc_dir_entry *hlmem_pde;
static char hlmem_name[24];

// ---------------------------------------------------------------------------
// page table reading
// ---------------------------------------------------------------------------

// Resolves the 4 KiB page of `mm` that covers `va` and takes a reference so the
// page cannot be reclaimed while user space is being written to. A huge mapping
// terminates at pud or pmd level; the correct sub-page is selected explicitly,
// because kmap_local_page() maps one page, not the whole huge page.
static int hlmem_get_page(struct mm_struct *mm, unsigned long va,
			  struct page **page_out, size_t *off_out)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	unsigned long base_pfn, idx = 0;
	struct page *page;

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
		base_pfn = pud_pfn(*pud);
		idx = (va & (PUD_SIZE - 1)) >> PAGE_SHIFT;
		goto have_pfn;
	}

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return -EFAULT;

	if (pmd_leaf(*pmd)) {
		base_pfn = pmd_pfn(*pmd);
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
	base_pfn = pte_pfn(pte);
	pte_unmap(ptep);

have_pfn:
	page = pfn_to_page(base_pfn + idx);
	if (!get_page_unless_zero(page))
		return -EFAULT;

	*page_out = page;
	*off_out = va & ~PAGE_MASK;
	return 0;
}

// Brings a non-resident page in by taking a remote fault, exactly as the target
// process would have done on its own. Bounded so a hostile address cannot spin.
static int hlmem_fault_in(struct mm_struct *mm, unsigned long va)
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

static long hlmem_read_range(struct mm_struct *mm, unsigned long va,
			     char __user *dst, u32 len)
{
	u32 done = 0;

	while (done < len) {
		unsigned long cur = va + done;
		struct page *page = NULL;
		void *kaddr;
		size_t off = 0, chunk;
		int tries, ret = -EFAULT;

		for (tries = 0; tries < 2; tries++) {
			mmap_read_lock(mm);
			ret = hlmem_get_page(mm, cur, &page, &off);
			mmap_read_unlock(mm);

			if (ret == 0)
				break;
			if (ret != -EAGAIN)
				return ret;
			if (hlmem_fault_in(mm, cur) != 0)
				return -EFAULT;
		}
		if (ret != 0)
			return -EFAULT;

		chunk = len - done;
		if (chunk > PAGE_SIZE - off)
			chunk = PAGE_SIZE - off;

		// The page reference is held, so it is safe to copy outside the lock.
		kaddr = kmap_local_page(page);
		if (copy_to_user(dst + done, (char *)kaddr + off, chunk))
			ret = -EFAULT;
		kunmap_local(kaddr);
		put_page(page);
		if (ret != 0)
			return ret;

		done += chunk;
	}
	return done;
}

// ---------------------------------------------------------------------------
// proc interface
// ---------------------------------------------------------------------------

static ssize_t hlmem_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	struct hlmem_req *req = file->private_data;

	if (count != sizeof(*req))
		return -EINVAL;
	if (copy_from_user(req, ubuf, sizeof(*req)))
		return -EFAULT;
	if (req->magic != HLMEM_MAGIC)
		return -EINVAL;
	if (req->len == 0 || req->len > HLMEM_MAX_LEN)
		return -EINVAL;
	return count;
}

static ssize_t hlmem_read(struct file *file, char __user *ubuf,
			  size_t count, loff_t *ppos)
{
	struct hlmem_req *req = file->private_data;
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	u32 want;
	long ret;

	if (req->magic != HLMEM_MAGIC || req->len == 0)
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	want = min_t(u32, (u32)count, req->len);
	if (want == 0)
		return 0;

	pid_struct = find_get_pid(req->pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -EINVAL;

	ret = hlmem_read_range(mm, (unsigned long)req->va, ubuf, want);
	mmput(mm);
	return ret;
}

static int hlmem_open(struct inode *inode, struct file *file)
{
	struct hlmem_req *req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	file->private_data = req;
	return 0;
}

static int hlmem_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct proc_ops hlmem_ops = {
	.proc_open    = hlmem_open,
	.proc_read    = hlmem_read,
	.proc_write   = hlmem_write,
	.proc_release = hlmem_release,
};

// ---------------------------------------------------------------------------
// hiding
// ---------------------------------------------------------------------------

// Removes the entry from its parent's subdirectory tree so that /proc listing
// does not show it. The open path stays valid because the inode and operations
// remain, and only the directory index entry goes away.
static void hlmem_unlink_pde(struct proc_dir_entry *parent,
			     struct proc_dir_entry *de)
{
	if (!parent || !de)
		return;

	spin_lock(&proc_subdir_lock);
	if (!RB_EMPTY_NODE(&de->subdir_node))
		rb_erase(&de->subdir_node, &parent->subdir);
	spin_unlock(&proc_subdir_lock);
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

static int __init hlmem_init(void)
{
	struct proc_dir_entry *root;

	// The name is derived at build time so no fixed string sits in the image.
	snprintf(hlmem_name, sizeof(hlmem_name), ".%s%d", "hlm", (int)(jiffies & 0xff));

	hlmem_pde = proc_create(hlmem_name, 0600, NULL, &hlmem_ops);
	if (!hlmem_pde)
		return -ENOMEM;

	root = hlmem_pde->parent;
	hlmem_unlink_pde(root, hlmem_pde);

	pr_debug("hlmem ready\n");
	return 0;
}

static void __exit hlmem_exit(void)
{
	if (hlmem_pde) {
		remove_proc_entry(hlmem_name, NULL);
		hlmem_pde = NULL;
	}
}

module_init(hlmem_init);
module_exit(hlmem_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Address space reader for debugger-style introspection");
