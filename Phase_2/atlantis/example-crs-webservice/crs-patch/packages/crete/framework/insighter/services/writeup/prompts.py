writeup_example = """By interacting with the IOCTL M2M1SHOT_IOC_PROCESS, the driver which provides hardware acceleration for media functions like JPEG decoding and image scaling may map the userspace pages to I/O pages, execute a firmware command and tear down mapped I/O pages.

The following IOCTL call is sent to the driver:
```
m2m1shot_task.fmt_cap.fmt = V4L2_PIX_FMT_YUV420M;
…
m2m1shot_task.buf_cap.num_planes = 3;
m2m1shot_task.buf_cap.type = M2M1SHOT_BUFFER_USERPTR;
m2m1shot_task.buf_cap.plane[SC_PLANE_Y].userptr = ion_map;
m2m1shot_task.buf_cap.plane[SC_PLANE_Y].len = 0x8000LL;
m2m1shot_task.buf_cap.plane[SC_PLANE_CB].userptr = buf_cap_map_2;
m2m1shot_task.buf_cap.plane[SC_PLANE_CB].len = 0x8000LL;
m2m1shot_task.buf_cap.plane[SC_PLANE_CR].userptr = buf_cap_map_3;
m2m1shot_task.buf_cap.plane[SC_PLANE_CR].len = 0x8000LL;
m2m1shot_task.fmt_out.fmt = V4L2_PIX_FMT_YUV420M;
…
m2m1shot_task.buf_out.num_planes = 3;
m2m1shot_task.buf_out.type = M2M1SHOT_BUFFER_USERPTR;
m2m1shot_task.buf_out.plane[SC_PLANE_Y].userptr = buf_out_map_1;
m2m1shot_task.buf_out.plane[SC_PLANE_Y].len = 0x8000LL;
m2m1shot_task.buf_out.plane[SC_PLANE_CB].userptr = buf_out_map_2;
m2m1shot_task.buf_out.plane[SC_PLANE_CB].len = 0x8000LL;
m2m1shot_task.buf_out.plane[SC_PLANE_CR].userptr = buf_out_map_3;
m2m1shot_task.buf_out.plane[SC_PLANE_CR].len = 0x8000LL;
m2m1shot_task.op.op = M2M1SHOT_OP_CSC_NARROW;
…

ioctl_ret = ioctl(m2m1shot_scaler0_fd, 0xC0C04D00uLL, &m2m1shot_task);
```

First, the driver parses m2m1shot_task.buf_cap and maps three sets of I/O memory with each set containing 8 pages. Similarly, the driver also parses m2m1shot_task.buf_out and maps I/O memory correspondingly.

Second, the firmware executes the command based on the op value M2M1SHOT_OP_CSC_NARROW and the format value V4L2_PIX_FMT_YUV420M. It copies the memory content from m2m1shot_task.buf_out to m2m1shot_task.buf_cap one by one. For example, the firmware copies data from the I/O pages mapped from m2m1shot_task.buf_out.plane[0].userptr to the I/O pages mapped from m2m1shot_task.buf_cap.plane[0].userptr.

To establish the I/O memory mapping, the driver function sysmmu_map_pte is called through the call chain m2m1shot_dma_addr_map -> exynos_iovmm_map_userptr -> exynos_iommu_map_userptr -> sysmmu_map_pud:

```
#define mk_lv2ent_pfnmap(pent) (*(pent) |= (1 << 5)) /* unused field */

static int sysmmu_map_pte(struct mm_struct *mm,
    pmd_t *pmd, unsigned long addr, unsigned long end,
    struct exynos_iommu_domain *domain, sysmmu_iova_t iova, int prot)
{
  pte_t *pte;
  int ret = 0;
  spinlock_t *ptl;
  bool write = !!(prot & IOMMU_WRITE);
  bool pfnmap = !!(prot & IOMMU_PFNMAP);  /** [1] **/ If vma->vm_flags & VM_PFNMAP is true, exynos_iovmm_map_userptr appends the IOMMU_PFNMAP flag to prot.
  bool shareable = !!(prot & IOMMU_CACHE);
  unsigned int fault_flag = write ? FAULT_FLAG_WRITE : 0;
  sysmmu_pte_t *ent, *ent_beg;

  pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
  if (!pte)
    return -ENOMEM;

  ent = alloc_lv2entry_userptr(domain, iova);
  if (IS_ERR(ent)) {
    ret = PTR_ERR(ent);
    goto err;
  }

  ent_beg = ent;

  do {
    if (pte_none(*pte) || !pte_present(*pte) ||
          (write && !pte_write(*pte))) {
      int cnt = 0;
      int maxcnt = 1;

      if (pfnmap) {
        ret = -EFAULT;
        goto err;
      }

      while (cnt++ < maxcnt) {
        spin_unlock(ptl);
        /* find_vma() always successes */
        ret = handle_mm_fault(find_vma(mm, addr),
            addr, fault_flag);
        spin_lock(ptl);
        if (ret & VM_FAULT_ERROR) {
          ret = mm_fault_translate(ret);
          goto err;
        } else {
          ret = 0;
        }
        [...]
      }
    }

    BUG_ON(!lv2ent_fault(ent));

    *ent = mk_lv2ent_spage(pte_pfn(*pte) << PAGE_SHIFT);

    if (!pfnmap)
      get_page(pte_page(*pte));
    else
      mk_lv2ent_pfnmap(ent);  /** [2] **/ For PFNMAP pages, the page reference count is not elevated.

    [...]
  } while (pte++, addr += PAGE_SIZE, addr != end);

  pgtable_flush(ent_beg, ent);
err:
  pte_unmap_unlock(pte - 1, ptl);
  return ret;
}
```

Unfortunately there's a bug in sysmmu_map_pte: the page reference count is not incremented for PFNMAP pages [1][2]. The driver only decrements the page reference count for non-PFNMAP pages when tearing down the I/O virtual memory in exynos_iommu_unmap_userptr [3]:

```
void exynos_iommu_unmap_userptr(struct iommu_domain *dom,
        dma_addr_t d_iova, size_t size)
{
  struct exynos_iommu_domain *domain = to_exynos_domain(dom);
  sysmmu_iova_t iova = (sysmmu_iova_t)d_iova;
  sysmmu_pte_t *sent = section_entry(domain->pgtable, iova);
  unsigned int entries = (unsigned int)(size >> SPAGE_ORDER);
  dma_addr_t start = d_iova;

  while (entries > 0) {
    [...]

    pent = page_entry(sent, iova);
    for (i = 0; i < lv2ents; i++, pent++) {
      /* ignore fault entries */
      if (lv2ent_fault(pent))
        continue;

      BUG_ON(!lv2ent_small(pent));

      if (!lv2ent_pfnmap(pent))
        put_page(phys_to_page(spage_phys(pent))); /** [3] **/ put_page only applies on the non-PFNMAP pages.

      *pent = 0;
    }
```

An attacker can allocate PFNMAP pages (e.g. ION), map them to I/O virtual memory and free the pages by munmap in the meantime. Thus, the I/O virtual pages may map to freed physical pages.
"""


def create_writeup_prompt(crash_report: str) -> str:
    return f"""Below is an example of an detailed writeup of how a program crashed.
Create a writeup like the example with the given crash report.
If you need to see any files, use the tools provided.
Ask precisely what function or declaration or line numbers you need.
Do not assume anything and ask for everything you need to write a detailed writeup.

<writeup_example>
{writeup_example}
</writeup_example>

Create a writeup for the crash report below:
<crash_report>
{crash_report}
</crash_report>
"""
