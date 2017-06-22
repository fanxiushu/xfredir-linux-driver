/// by fanxiushu 2016-08-02
#include "xfs_redir.h"
#include "ioctl.h"

static void xfs_put_super(struct super_block *sb);

///// inode->i_size大小改变时候，
void xfs_update_inode_size(struct inode* inode, loff_t newsize )
{
	loff_t oldsize = inode->i_size;
	///
	i_size_write(inode, newsize);

	if (S_ISREG(inode->i_mode) && oldsize != newsize ) { // file
		////
		if (newsize < oldsize) {
			/// vmtruncate() 
			unmap_mapping_range(inode->i_mapping, newsize + PAGE_SIZE - 1, 0, 1);
			truncate_inode_pages(inode->i_mapping, newsize);
			unmap_mapping_range(inode->i_mapping, newsize + PAGE_SIZE - 1, 0, 1);
		}
		///
		invalidate_inode_pages2(inode->i_mapping);
	}
	/////
}

void xfs_set_inode_stat(struct inode* inode, struct file_stat_t* fattr)
{
	inode->i_ino = fattr->ino; //
	inode->i_mode = fattr->mode;
#if LINUX_VERSION_CODE >= MIN_KVER
	set_nlink(inode,  fattr->nlink ); //
	inode->i_uid = make_kuid(&init_user_ns, fattr->uid);
	inode->i_gid = make_kgid(&init_user_ns, fattr->gid);
#else
	inode->i_nlink = fattr->nlink;  //
	inode->i_uid = fattr->uid;
	inode->i_gid = fattr->gid;
#endif
	inode->i_blocks = fattr->blocks;
//	inode->i_size = fattr->size;
	inode->i_mtime.tv_sec = fattr->mtime;
	inode->i_atime.tv_sec = fattr->atime;
	inode->i_ctime.tv_sec = fattr->ctime;
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;

	XFS_INODE(inode)->i_no = fattr->ino;
	
	////
	xfs_update_inode_size(inode, fattr->size); ////

}

static int xfs_inode_compare(struct inode* inode, void* _p)
{
	u64 ino = *(u64*)_p;
	if (XFS_INODE(inode)->i_no == ino) return 1;  /// ==
	return 0; ///
}
static int xfs_inode_set(struct inode* inode, void* _p)
{
	XFS_INODE(inode)->i_no = *(u64*)_p;
	///
	return 0;
}
struct inode* xfs_iget(struct super_block *sb, struct file_stat_t* attr )
{
	//////
	struct inode* inode;
	u64 ino = attr->ino;
	struct xfs_inode_t* xi = NULL;

L:
	inode = iget5_locked(sb, ino, xfs_inode_compare, xfs_inode_set, &ino ); ///新建inode
	if (!inode) {
		return NULL;
	}

	xi = XFS_INODE(inode); ///
	///
	if (inode->i_state & I_NEW) { //节点是新建的
							
		inode->i_mode = attr->mode; /// mode 

		///添加文件或目录操作函数
		if (S_ISREG(inode->i_mode)) { /// normal file 
			///
			inode->i_op = &xfs_file_iops;
			inode->i_fop = &xfs_file_fops;
			inode->i_data.a_ops = &xfs_file_aops; ///
												  ///
		}
		else if (S_ISDIR(inode->i_mode)) { /// directory
										   ////
			inode->i_op = &xfs_dir_iops;
			inode->i_fop = &xfs_dir_fops;
			////
		}
		/////
		xi->user_pid = 0;
		xi->i_usrctx = xi->i_usrctx2 = 0;
		
		unlock_new_inode(inode); /// 解锁

	}
	////
	else if ((inode->i_mode ^ attr->mode) & S_IFMT) { //新建的节点属性已经改变，比如从文件S_IFREG改成目录S_IFDIR.这个inode
		printk("iget5_locked get not same i_mode [%d] -> [%d], ino=%lld\n", inode->i_mode, attr->mode, ino);
		make_bad_inode(inode);
		iput(inode);
		goto L;
	}


    ///设置属性
	xfs_set_inode_stat(inode, attr); ////设置inode的属性
	
	////

	return inode;
}

struct inode* xfs_ifind(struct super_block *sb, u64 ino)
{
	struct inode* inode;
	inode = ilookup5(sb, ino, xfs_inode_compare, &ino); 
	return inode;
}

///// inode alloc
static struct inode* xfs_alloc_inode(struct super_block *sb)
{
	struct xfs_inode_t *xi;
	xi = (struct xfs_inode_t *)kmem_cache_alloc(xfs->inode_pool, GFP_KERNEL);
	if (!xi)
		return NULL;

	///
	memset(xi, 0, sizeof(struct xfs_inode_t)); /// init xfs_inode 

	/// init inode 
	inode_init_once(&xi->vfs_inode);


	////
	return &xi->vfs_inode;
}

static void xfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(xfs->inode_pool, XFS_INODE(inode));
}


///i_nlink==0 and i_count==0 ,delete_inode回调，此函数内必须调用 truncate_inode_pages 和clear_inode,否则会异常
static void xfs_delete_inode(struct inode *ino)
{
	struct xfs_inode_t* xi = XFS_INODE(ino);

	truncate_inode_pages(&ino->i_data, 0); ////

//	printk("xfs_clear_inode: i_ino=%ld\n", ino->i_ino );
	///
	xi->user_pid = 0;
	xi->i_usrctx = xi->i_usrctx2 = 0; ///

	////
	clear_inode(ino);
}

static int xfs_statfs(struct dentry *dentry, struct kstatfs *st)
{
	//for filesystem info
	st->f_type = XFS_SB_MAGIC;
	st->f_namelen = 255;

	st->f_blocks = 9000000; //乱造的数字
	st->f_bsize = 4096;
	st->f_bavail = st->f_bfree = 8000000;
	////
	return 0;
}

//////////////
static const struct super_operations xfs_sb_ops =
{
	.alloc_inode = xfs_alloc_inode,
	.destroy_inode = xfs_destroy_inode,
	.drop_inode = generic_delete_inode,
	.statfs = xfs_statfs,
#if LINUX_VERSION_CODE >= MIN_KVER
	.evict_inode = xfs_delete_inode,
#else
	.delete_inode = xfs_delete_inode,
#endif
	.put_super = xfs_put_super,
};

////
static void get_root_attr(struct file_stat_t* attr, struct mon_dir_t* md )
{
	struct timespec cur;
	cur = current_kernel_time();
	attr->ino = md->root_ino;
	attr->nlink = 1; ///
	attr->mode = S_IFDIR;
	attr->uid = md->root_uid;
	attr->gid = md->root_gid;
	attr->ctime = attr->mtime = attr->atime = cur.tv_sec;
	attr->size = 0;
	attr->blocks = 0;

}
static int fs_fill_super(struct super_block *sb, void *data, int silent)
{
	/////
	int ret = -EINVAL;
	char* mnt_path = (char*)data; //挂载路径,应用层调用mount传递给mount函数最后一个参数
	struct mon_dir_t* md = NULL;
	struct mon_dir_t* md_p;
	struct inode*  root_inode;
	struct dentry* root = NULL;
	struct file_stat_t root_attr;

	///
	sb->s_magic = XFS_SB_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_CACHE_SIZE;  /// 4K
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT; /// 
//	sb->s_time_gran = 100; //时间戳粒度 ???
	sb->s_flags |= MS_POSIXACL; // ???
	/////
#if LINUX_VERSION_CODE >= MIN_KVER 
	sb->s_d_op = &xfs_dentry_operations; ////
#endif
	/////////////

	lock();

	list_for_each_entry(md_p, &xfs->mon_dirs, list) {
		///
		if (strcmp(mnt_path, md_p->path.buffer) == 0) { ////从全局链表检测是否已经创建了监控目录
			md = md_p;
			break;
		}
	}
	if (!md) {
		unlock();
		printk("### fs_fill_super not found [%s]\n", mnt_path);
		return -ENOENT; ///不存在
	}
	md->sb = sb;  ///

	__mon_dir_addref(md); ///

	unlock();

	sb->s_fs_info = md; ///保存指针
	sb->s_op = &xfs_sb_ops; ///

	get_root_attr(&root_attr, md );
	root_inode = xfs_iget(sb, &root_attr );
	if (!root_inode) {
		ret = -ENOMEM;
		goto ERR;
	}

#if LINUX_VERSION_CODE >= MIN_KVER
	root = d_make_root(root_inode); ///
#else
	root = d_alloc_root(root_inode);
#endif
	if (!root) {
		ret = -EINVAL;
		iput(root_inode);
		goto ERR;
	}
	sb->s_root = root; ///
	/////
	return 0;

ERR:
	lock();
	md->sb = NULL;
	__mon_dir_release(md); ///
	unlock();

	return ret;
}

///删除上边前的回调函数
static void xfs_put_super(struct super_block *sb)
{
	struct mon_dir_t* md = MON_DIR(sb);

	printk("### xfs_put_super called.\n");
	////
	
	if (md) {
		lock();
		__mon_dir_release(md); ///
		unlock();
	}

	////
}

#if LINUX_VERSION_CODE >= MIN_KVER
static struct dentry* fs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name,
	void *raw_data)
{
	//////应用层调用mount函数，传递 raw_data参数是挂载的路径,比如挂载到 /home/dir, row_data 指向 "/home/dir"

	return mount_nodev(fs_type, flags, raw_data, fs_fill_super);
}

#else
static int fs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name,
	void *raw_data, struct vfsmount *mnt)
{
	//////应用层调用mount函数，传递 raw_data参数是挂载的路径,比如挂载到 /home/dir, row_data 指向 "/home/dir"

	return get_sb_nodev(fs_type, flags, raw_data, fs_fill_super, mnt);


}

#endif


static void fs_kill_sb(struct super_block *sb)
{
//	struct mon_dir_t* md = MON_DIR(sb);
	///

	kill_anon_super(sb);

}

static struct file_system_type xfs_fs_type = {
	////
	.owner = THIS_MODULE,
	.name = XFS_FILE_TYPE,
#if LINUX_VERSION_CODE >= MIN_KVER
	.mount = fs_get_sb, 
#else
	.get_sb = fs_get_sb,
#endif
	.kill_sb = fs_kill_sb,
	.fs_flags = FS_REQUIRES_DEV | FS_HAS_SUBTYPE,

};


int xfs_reg_fs(void)
{
	int err;
	err = register_filesystem(&xfs_fs_type);
	if (err) {
		printk("register_filesystem err=%d\n", err);
	}
	////
	return err;
}

void xfs_unreg_fs(void)
{
	unregister_filesystem(&xfs_fs_type); ///
}

