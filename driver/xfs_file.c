/// by fanxiushu 2016-08-11

#include "xfs_redir.h"

///实现真正意义上的读写
static int xfs_data_io(struct inode* inode, int op_type, char* buffer, loff_t offset, size_t length)
{
	struct mon_dir_t*md;
	struct op_queue_t* op;
	int ret;
	md = I_MON_DIR(inode);

	if (length == 0) { //读写0 长度
		return 0; ///
	}

	op = xfs_alloc_op_queue(op_type, inode); ///
	if (!op) {
		////
		return -ENOMEM;
	}

	op->readwrite.offset = offset;
	op->readwrite.length = length;
	op->readwrite.buffer = buffer; ///

	ret = xfs_wait_op_queue_complete(md, op, md->t_tmo); //// 

	if (ret >= 0) {
		///
		xfs_attr_invalidate(inode); ////inode 属性重新从用户空间查询
	}

	return ret;
}

///用于直接读写
size_t xfs_copy_user_with_pages(struct dio_page_t* pgs, char __user* user_buffer, 
	size_t user_length, int is_to_user )
{
	int i;
	size_t copied = 0;
	unsigned int pg_off = pgs->pg_off;
	size_t total_copied = min(pgs->length, user_length );

	if (pg_off >= PAGE_SIZE) return -EINVAL;

	for (i = 0; i < pgs->npages; ++i) {
		struct page* page = pgs->pages[i];
		char* buf = (char*)kmap(page) + pg_off ;
		char* user = user_buffer + copied; 
		size_t r_cp = PAGE_SIZE - pg_off;
		r_cp = min( r_cp, (total_copied - copied) ); 

		if (is_to_user) { if (copy_to_user( user, buf, r_cp) != 0) copied = -EFAULT; }
		else { if (copy_from_user(buf, user, r_cp) != 0) copied = -EFAULT; }

		kunmap(page);
		
		if (copied < 0 )break;
		pg_off = 0; ///
		copied += r_cp;
		if (copied >= total_copied) break; ///
	}
	///
	return copied;
}

static int xfs_get_user_pages(struct dio_page_t* pgs, const char __user *user_buffer )
{
	size_t length = pgs->length; ///
	unsigned long user_addr = (unsigned long)user_buffer;
	unsigned pageoffset = user_addr & ~PAGE_MASK; //计算出在 page内的偏移，user_addr可能并不是4K页对齐
	int npages;
	
	///判断 user_buffer 是否可以直接在内核copy
	if ( segment_eq( get_fs(), KERNEL_DS ) ) { //
		////
		pgs->length = min_t(size_t, length, XFS_MAX_DIO_PAGES_COUNT << PAGE_SHIFT); ///取最小的
		pgs->npages = 0;
		pgs->pages = NULL;
		printk("xfs_get_user_pages: can copy direct buf_ptr=%p, buf_len=%ld\n", user_buffer, pgs->length );
		return 0; ///
	}

	/////
	length = min_t(size_t, length, XFS_MAX_DIO_PAGES_COUNT << PAGE_SHIFT); ///取最小的
	npages = (length + pageoffset + PAGE_SIZE - 1) >> PAGE_SHIFT;
	npages = clamp(npages, 1, XFS_MAX_DIO_PAGES_COUNT);
	if (pageoffset > 0 )printk("xfs_get_user_pages: not align 4K page: user_addr=%p, page_offset=0x%X\n", user_buffer, pageoffset );

	down_read(&current->mm->mmap_sem);
	npages = get_user_pages(current, current->mm, user_addr, npages, pgs->is_modify_page,
		0, pgs->pages, NULL);
	up_read(&current->mm->mmap_sem);
	if (npages < 0) return npages;

	pgs->npages = npages;
	pgs->pg_off = pageoffset;
	
	length = ( npages << PAGE_SHIFT) - pageoffset;
	pgs->length = min(pgs->length, length);

	return 0;
}
static void xfs_release_user_pages(struct dio_page_t* pgs )
{
	int i;
	if (!pgs->pages) return;

	for (i = 0; i < pgs->npages; ++i) {
		struct page *page = pgs->pages[i];
		if (pgs->is_modify_page) set_page_dirty_lock(page);
		put_page(page); 
	}
	//////
}

static ssize_t xfs_direct_io(struct inode* inode, int op_type, char __user* user_buffer, size_t length, loff_t* ppos )
{
	int ret;
	loff_t offset = *ppos; 
	char __user* user = user_buffer;
	ssize_t result = 0;
	struct page* pages[XFS_MAX_DIO_PAGES_COUNT];
	struct mon_dir_t* md = I_MON_DIR(inode);

	//
	xfs_attr_invalidate(inode); ///
	////
	while (length > 0) {
		struct op_queue_t* op;
		struct dio_page_t pgs = {
			.length = length,
			.pages = pages, 
			.offset = offset,
			.is_modify_page = ((op_type == OP_READ) ? 1 : 0),
		};

		ret = xfs_get_user_pages(&pgs, user );
		if (ret < 0) {
			printk("xfs_direct_io: xfs_get_user_pages err=%d\n", ret );
			return ret;
		}
		/////
		op = xfs_alloc_op_queue(op_type, inode); 
		if (!op) {
			xfs_release_user_pages(&pgs);
			return -ENOMEM;
		}
		
		///////
		op->readwrite.length = pgs.length;
		op->readwrite.offset = pgs.offset;
		if (pgs.pages) {
			op->readwrite.pages = &pgs;	
			op->readwrite.buffer = NULL;
		}
		else { //可以直接操作的内存块，是内核空间分配的
			op->readwrite.pages = NULL;
			op->readwrite.buffer = user; ///
		}
		///////

		ret = xfs_wait_op_queue_complete(md, op, md->t_tmo);

		xfs_release_user_pages(&pgs); ////

		/////
		if (ret < 0) {
			return ret; 
		}

		length -= ret;
		user += ret;
		result += ret;
		offset += ret;

		if (ret != pgs.length) { //读写完成
			break;
		}
		//////
	}

	*ppos = offset; ////
	/////
	return result;
}

////
static int xfs_readpage(struct file *file, struct page *page)
{
	int ret = -EIO;
	struct inode *inode = page->mapping->host;
	char* buffer = kmap(page); ///
	loff_t offset = page_offset(page);
	size_t length = PAGE_CACHE_SIZE;

	////
	if (!inode || is_bad_inode(inode)) {
		///
		ret = -EIO;
		goto L;
	}

	////
//	printk("xfs_readpage: ino=%ld\n", inode->i_ino );

	ret = xfs_data_io(inode, OP_READ, buffer, offset, length); ///

	if ( ret < 0 ) {
		printk("xfs_readpage: do_read ino=%ld, err=%d\n", inode->i_ino, ret );
		goto L;
	}

	else if (ret < length) { //读取的数据比需要的小，已经读到文件尾
		///
		memset(buffer + ret, 0, length - ret); ///
		///
	//	i_size_write(inode, pos + ret); ///重新计算inode文件长度
	}

	SetPageUptodate(page); ////

	ret = 0; /// success;

	////////////////////////////
L:
	kunmap(page); 
	unlock_page(page); ///
	return ret;
}

///写page，在locked page的状态下,pageoffset是相对于page的偏移，总偏移应该是 page_offset(page)+pageoffset
static int xfs_writepage_data(struct page* page, loff_t pageoffset, size_t length)
{
	int ret;
	struct inode* inode;
	char* buffer;
	loff_t offset;

	if (!page || !page->mapping) return -EIO;

	inode = page->mapping->host;
	if (!inode || is_bad_inode(inode)) {
		return -EIO;
	}

	buffer = kmap(page);
	offset = page_offset(page) + pageoffset; 

	ret = xfs_data_io(inode, OP_WRITE, buffer + pageoffset, offset, length); 

	kunmap(page);

	return ret;
}
static int xfs_writepage(struct page *page, struct writeback_control *wbc)
{
//	struct inode* inode = page->mapping->host;
	int ret;
	size_t length = PAGE_SIZE;

//	printk("xfs_writepage:\n");

	ret = xfs_writepage_data(page, 0, length);
	if (ret > 0) {
		ret = 0; /// success
	}

	unlock_page(page); ///

	return ret;
}

static int xfs_write_begin(struct file *file, struct address_space *mapping,
	loff_t pos, unsigned len, unsigned flags,
	struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	*pagep = grab_cache_page_write_begin(mapping, index, flags);
	if (!*pagep)
		return -ENOMEM;
	return 0;
}

static int xfs_write_end(struct file *file, struct address_space *mapping,
	loff_t pos, unsigned len, unsigned copied,
	struct page *page, void *fsdata)
{
	int ret = 0;
	size_t pageoffset = pos & ( PAGE_SIZE - 1 );
	printk("xfs_write_end: buffered IO copied=%d\n", copied );

	if (copied) {
		ret = xfs_writepage_data(page, pageoffset, copied);
		if (ret >= 0 ) {
			///
			if (!PageUptodate(page) && copied == PAGE_CACHE_SIZE)
				SetPageUptodate(page);
			////
			ret = copied;
		}
	}

	unlock_page(page); ///
	page_cache_release(page);

	return ret;
}

///直接IO
static ssize_t xfs_directIO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs)
{
	struct file* file = iocb->ki_filp;
	struct inode* inode = file->f_path.dentry->d_inode;
	const struct iovec *vector = iov;
	ssize_t ret = 0;
	loff_t  off = offset; ///

	if (is_bad_inode(inode)) {
		return -EIO; ///
	}
	printk("rw=%d, xfs_direct_IO\n", rw);

	while (nr_segs > 0) {
		char __user *user = vector->iov_base;
		size_t len = vector->iov_len;
		ssize_t nr;
		int op_type = ( (rw == WRITE) ? OP_WRITE : OP_READ ); ///

		vector++;
		nr_segs--;

		//////
		nr = xfs_direct_io(inode, op_type, user, len, &off); 

		if (nr < 0) {
			if (!ret) ret = nr;
			break;
		}
		ret += nr;
		///
		if (nr != len) break;
	}

	return ret;
}

////
static ssize_t xfs_read(struct file *file, char __user *buf,
	size_t length, loff_t *ppos)
{
	struct inode* inode = file->f_path.dentry->d_inode;
	struct mon_dir_t* md;
	////
	if (is_bad_inode(inode)) return -EIO;
	md = I_MON_DIR(inode); ///

	if (md->is_dio) {
		return xfs_direct_io(inode, OP_READ, buf, length, ppos);
	}
	////
	return do_sync_read(file, buf, length, ppos);
}

static ssize_t xfs_write(struct file *file, const char __user *buf,
	size_t length, loff_t *ppos)
{
	struct inode* inode = file->f_path.dentry->d_inode;
	struct mon_dir_t* md;
	////
	if (is_bad_inode(inode)) return -EIO;
	md = I_MON_DIR(inode); 

	if (md->is_dio) {
		return xfs_direct_io(inode, OP_WRITE, (char*)buf, length, ppos);
	}
	//
	return do_sync_write(file, buf, length, ppos);
}

static loff_t xfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int ret;
	printk("xfs_file_llseek: offset=%lld\n", offset );
	lock();
	ret = generic_file_llseek(file, offset, whence); ////
	unlock();
	return ret;
}

static ssize_t xfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
	unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	struct inode* inode = iocb->ki_filp->f_path.dentry->d_inode;
	struct mon_dir_t* md;

	if (is_bad_inode(inode)) return -EIO;
	md = I_MON_DIR(inode);

	///需要刷新inode的属性吗?也许再读写过程中，inode的attr有变化？？？
	printk("xfs_file_aio_read.\n");

	if (md->is_dio) {
		////
		ret = xfs_directIO(READ, iocb, iov, pos, nr_segs); ///
	}
	else {
		ret = generic_file_aio_read(iocb, iov, nr_segs, pos);
	}

	return ret;
}

static ssize_t xfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
	unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	struct inode* inode = iocb->ki_filp->f_path.dentry->d_inode;
	struct mon_dir_t* md;

	if (is_bad_inode(inode)) return -EIO;
	md = I_MON_DIR(inode);

	///需要刷新inode的属性吗?也许再读写过程中，inode的attr有变化？？？
	printk("xfs_file_aio_write:\n");
	////
	
	if (md->is_dio) {
		////
		ret = xfs_directIO(WRITE, iocb, iov, pos, nr_segs); ///
	}
	else {
		ret = generic_file_aio_write(iocb, iov, nr_segs, pos);
	}

	return ret;
}
static int xfs_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	int ret;
	/// need refresh inode attribute ?? 
	printk("xfs_file_map: \n");

	invalidate_inode_pages2(file->f_mapping); ///

	ret = generic_file_mmap(file, vma);

	return ret;
}

#if LINUX_VERSION_CODE >= MIN_KVER 
static int xfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
#else
static int xfs_fsync(struct file *file, struct dentry * dentry, int datasync)
#endif
{
	///
	struct inode* inode = file->f_path.dentry->d_inode;
	if (!inode || is_bad_inode(inode)) return -EIO;

	filemap_write_and_wait(inode->i_mapping); ///刷新所有脏页到磁盘

	return 0;
}

static int xfs_file_open(struct inode* inode, struct file* file)
{
	struct xfs_inode_t* xi = XFS_INODE(inode);

	atomic_inc(&xi->open_count); ///

	return 0;
}
static int xfs_file_release(struct inode* inode, struct file* file)
{
	///
	struct xfs_inode_t* xi = XFS_INODE(inode);
	///
	if (atomic_dec_and_test(&xi->open_count)) {
		///
		printk("xfs_file_release: ino=%ld\n", inode->i_ino ); ///
		////
		filemap_write_and_wait(inode->i_mapping);
	}

	return 0;
}

///////////////
const struct address_space_operations xfs_file_aops = {
	.readpage =  xfs_readpage,
	.writepage = xfs_writepage,
	.write_begin = xfs_write_begin,
	.write_end = xfs_write_end,
	.set_page_dirty = __set_page_dirty_nobuffers,
	.direct_IO = xfs_directIO,
};

const struct file_operations xfs_file_fops =
{
	.llseek = xfs_file_llseek,
	.read = xfs_read,
	.aio_read = xfs_file_aio_read,
	.write = xfs_write,
	.aio_write = xfs_file_aio_write,
	.mmap = xfs_file_mmap,
	.open = xfs_file_open,
	.release = xfs_file_release,
	.fsync = xfs_fsync,
	.splice_read = generic_file_splice_read,
};

const struct inode_operations xfs_file_iops =
{
	.getattr = xfs_getattr,
	.setattr = xfs_setattr,
};

