
//// By Fanxiushu 2016-08-11

#include "xfs_redir.h"

/// dentry ,用于在 判断lookup中是否调用到用户空间
#if LINUX_VERSION_CODE >= MIN_KVER
static int xfs_dentry_revalidate(struct dentry* entry, unsigned int flags ) 
#else
static int xfs_dentry_revalidate(struct dentry* entry, struct nameidata* nd)
#endif
{
	struct inode* inode = entry->d_inode;
	struct mon_dir_t* md;

//	printk("xfs_dentry_revalidate: [%s]\n", entry->d_name.name );

	if (!inode) {///没有与 inode关联，发起lookup查找
		///
		return 0; 
	}
	if (inode && is_bad_inode(inode)) return 0; //无效的inode，发起 lookup查找

	md = I_MON_DIR(inode); ///

	if ( md->e_tmo <= 0 || xfs_dentry_time(entry) < get_jiffies_64() ) { //// 超时
		////
		xfs_dentry_change_timeout(entry, md->e_tmo);   ////
		/////
		return 0;
	}

	////
	return 1; 
}

const struct dentry_operations xfs_dentry_operations = {
	.d_revalidate = xfs_dentry_revalidate,
};

////
static int xfs_dir_open(struct inode* inode, struct file* file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct xfs_file_t* fp = (struct xfs_file_t*)kmalloc(sizeof(struct xfs_file_t), GFP_KERNEL);
	if (!fp) {
		return -ENOMEM;
	}
	file->private_data = fp;
	fp->is_dir = 1; 
	fp->is_readdir = 0;
	fp->d_usrctx = 0; 
	fp->d_usrctx2 = 0;

	printk("xfs_dir_open [%s/%s]\n", dentry->d_parent->d_name.name,file->f_path.dentry->d_name.name );
	/////

	return 0;
}
static int xfs_dir_release(struct inode* inode, struct file* file)
{
	struct xfs_file_t* fp = file->private_data;

	if (fp->is_readdir && inode ) {
		////
		struct mon_dir_t* md = I_MON_DIR(inode); 
		struct op_queue_t* op;
		op = xfs_alloc_op_queue(OP_READDIR, inode);
		if (op) {//结束，通知应用层 readdir 结束
			///
			op->is_noreply = 1;

			op->readdir.fill = NULL;
			op->readdir.fp = fp;

			xfs_wait_op_queue_complete(md, op, md->q_tmo); ///
		}
		////
	}
	////
	kfree(fp);
	return 0;
}

static int xfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct dentry* dentry = file->f_path.dentry;
	struct inode*  inode = dentry->d_inode;
	struct xfs_file_t* fp = file->private_data;
	struct file_dirfill_t dirfill;
	struct op_queue_t* op;
	struct mon_dir_t* md;
	int ret = 0; ///success
	
	if (!inode || is_bad_inode(inode)) {
		printk("xfs_readdir err bad inode \n");
		return -EIO;
	}

//	printk("--xfs_readdir: ino=%lld\n", (u64)inode->i_ino );
	fp->is_readdir = 1; 
	md = I_MON_DIR(inode);

	switch ((unsigned int)file->f_pos) {
	case 0:
		if (filldir(dirent, ".", 1, 0, inode->i_ino, DT_DIR) < 0)
			goto L;
		file->f_pos = 1;
	case 1:
		if (filldir(dirent, "..", 2, 1, parent_ino(dentry), DT_DIR) < 0)
			goto L;
		file->f_pos = 2;
	}

	/////
	op = xfs_alloc_op_queue(OP_READDIR, inode);
	if (!op) {
		return -ENOMEM;
	}

	dirfill.name_len = 0;
	op->readdir.fill = &dirfill;
	op->readdir.fp = fp;

	ret = xfs_wait_op_queue_complete(md, op, md->q_tmo); ///

	if (ret == 0 && dirfill.name_len > 0) { ///有文件

		if (filldir(dirent, dirfill.name, dirfill.name_len, file->f_pos, dirfill.ino, dirfill.type) < 0)
			goto L;
		///
		file->f_pos++; 
	}
	/////
	xfs_attr_invalidate(inode); ////inode 属性重新从用户空间查询

L:
	return ret;
}


/// inode function
static int query_user_stat( struct inode* inode, struct dentry* sub_entry, struct file_stat_t* st)
{
	int ret;
	int optype = sub_entry ? OP_LOOKUP : OP_QUERY_STAT;  ///
	struct mon_dir_t* md;
	struct op_queue_t* op;
	if (!inode || is_bad_inode(inode)) {
		return -EIO;
	}
	md = I_MON_DIR(inode);
	///
	op = xfs_alloc_op_queue( optype, inode);
	if (!op) {
		return -ENOMEM;
	}
	op->dentry = sub_entry; 
	op->stat = st; 

	///
	ret = xfs_wait_op_queue_complete(md, op, md->q_tmo); ///

	return ret; 
}

#if LINUX_VERSION_CODE >= MIN_KVER
static struct dentry *xfs_lookup(struct inode* dir_inode, struct dentry* dentry, unsigned int flags)
#else
static struct dentry *xfs_lookup(struct inode* dir_inode, struct dentry* dentry, struct nameidata* nd)
#endif
{
	int ret; 
	struct file_stat_t st; 
	struct inode* inode = NULL;
	struct mon_dir_t* md;

	if (!dir_inode || is_bad_inode(dir_inode)) {
		////
		return ERR_PTR(-EIO); 
	}

	//////
	md = I_MON_DIR(dir_inode); //

	ret = query_user_stat(dir_inode, dentry, &st);
	if (ret == -ENOENT) goto add_entry;

	if (ret == 0) { // success
		inode = xfs_iget(dir_inode->i_sb, &st); ///
		if (inode ) {
add_entry:
			//
			dentry->d_op = &xfs_dentry_operations; ////

			d_add(dentry, inode); 

			xfs_dentry_change_timeout(dentry, inode ? md->e_tmo : 0 );  ///设置超时时间

			ret = 0; ///
			////
		}
		else{
			ret = -ENOMEM; ///
			printk("xfs_lookup: xfs_iget get inode NULL\n");
		}
	}
	///
	if (ret != 0) {
		////
		xfs_dentry_invalidate(dentry); ///重新
	}
	////
//	printk("xfs_lookup: [%s], ret=%d\n", dentry->d_name.name, ret );

	return ERR_PTR(ret);
}

int xfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode* inode = dentry->d_inode;
	struct mon_dir_t* md;
	struct file_stat_t st;
	int ret;
	
	if (!inode || is_bad_inode(inode)) {
		printk("xfs_getattr err bad inode \n");
		return -EIO;
	}
//	printk("xfs_getattr: ino=%lld\n", (u64)inode->i_ino );

	md = I_MON_DIR(inode); 
	///
	if (inode->i_ino == md->root_ino) { ///root
		generic_fillattr(dentry->d_inode, stat);
		return 0;
	}
	//////
	if ( md->a_tmo <= 0 || xfs_attr_time(inode) < get_jiffies_64() ) { //超时

		/////
		ret = query_user_stat(inode, NULL, &st); //从用户层查询文件或目录属性

		if (ret == 0) { // success

			if ((st.mode ^ inode->i_mode) & S_IFMT) {
				/////
				printk("xfs_getattr: not same i_mode ino=%ld.\n", inode->i_ino);
				make_bad_inode(inode);
				///
				ret = -EIO;
			}
			else {
				///
				xfs_set_inode_stat(inode, &st);
				///
				generic_fillattr(inode, stat);
				
				xfs_attr_change_timeout(inode, md->a_tmo); ///重新计算超时
				/////
			}
			//////////
		}
		else {
			printk("query ino attribute ino=%lld, err=%d\n", (u64)inode->i_ino, ret);
		}
		///////
	}
	else {
		ret = 0;

		generic_fillattr(dentry->d_inode, stat); ///没超时，直接从 inode复制
	}
	////////

	return ret;
}

int xfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	int ret;
	struct inode* inode = dentry->d_inode;
	struct mon_dir_t* md;
	struct file_stat_t st;
	struct op_queue_t* op;
	
	////
	if (!inode || is_bad_inode(inode)) {
		printk("xfs_readdir err bad inode \n");
		return -EIO;
	}
	md = I_MON_DIR(inode); 

	ret = inode_change_ok(inode, attr);
	if (ret < 0) {
		printk("xfs_setattr: inode_change_ok err=%d\n", ret );
		return ret; 
	}
	
	memset(&st, 0, sizeof(st)); ////

#if LINUX_VERSION_CODE >= MIN_KVER
	if (attr->ia_valid & ATTR_UID) { st.flags |= SET_ATTR_UID; st.uid = from_kuid(&init_user_ns, attr->ia_uid); }
	if (attr->ia_valid & ATTR_GID) { st.flags |= SET_ATTR_GID; st.gid = from_kgid(&init_user_ns, attr->ia_gid); }
#else
	if (attr->ia_valid & ATTR_UID) { st.flags |= SET_ATTR_UID; st.uid = attr->ia_uid; }
	if (attr->ia_valid & ATTR_GID) { st.flags |= SET_ATTR_GID; st.gid = attr->ia_gid; }
#endif
	if (attr->ia_valid & ATTR_MODE) {  st.flags |= SET_ATTR_MODE;  st.mode = attr->ia_mode; }
	if (attr->ia_valid & ATTR_SIZE) {  st.flags |= SET_ATTR_SIZE;  st.size = attr->ia_size; }
	if (attr->ia_valid & ATTR_ATIME) { st.flags |= SET_ATTR_ATIME; st.atime = attr->ia_atime.tv_sec; }
	if (attr->ia_valid & ATTR_MTIME) { st.flags |= SET_ATTR_MTIME; st.mtime = attr->ia_mtime.tv_sec; }

	///刷新所有脏页到磁盘
	if (S_ISREG(inode->i_mode)) {
		///
		filemap_write_and_wait(inode->i_mapping);  
	}

	////////
	op = xfs_alloc_op_queue(OP_SET_STAT, inode); ////
	if (!op) {
		///
		return -ENOMEM;
	}

	op->stat = &st; ///

	ret = xfs_wait_op_queue_complete(md, op, md->q_tmo); ///

	if (ret != 0) {
		printk("xfs_setattr ino=%ld, err=%d\n", inode->i_ino, ret );
		return ret;
	}
	///
#if LINUX_VERSION_CODE >= MIN_KVER
	if (attr->ia_valid & ATTR_UID) { inode->i_uid = attr->ia_uid; }
	if (attr->ia_valid & ATTR_GID) { inode->i_gid = attr->ia_gid; }
#else
	if (attr->ia_valid & ATTR_UID) { inode->i_uid = attr->ia_uid; }
	if (attr->ia_valid & ATTR_GID) { inode->i_gid = attr->ia_gid; }
#endif
	if (attr->ia_valid & ATTR_MODE)  { inode->i_mode = attr->ia_mode; }
	if (attr->ia_valid & ATTR_ATIME) { inode->i_atime.tv_sec = attr->ia_atime.tv_sec; }
	if (attr->ia_valid & ATTR_MTIME) { inode->i_mtime.tv_sec = attr->ia_mtime.tv_sec; }
	
	////
	if (attr->ia_valid & ATTR_SIZE) { ///
		////
		xfs_update_inode_size(inode, attr->ia_size);
	}

	///
	xfs_dentry_invalidate(dentry); ////

	xfs_attr_invalidate(inode); ////inode 属性重新从用户空间查询
	/////
	return 0;
}

/////
static int xfs_mknod(struct inode* dir_inode, struct dentry* entry, umode_t mode, dev_t rdev)
{
	int ret;
	struct op_queue_t* op;
	struct mon_dir_t* md;
	struct file_stat_t st;
	struct inode* inode;
	if (!dir_inode || is_bad_inode(dir_inode)) {
		return -EIO;
	}
	md = I_MON_DIR(dir_inode);
	memset(&st, 0, sizeof(st));

	op = xfs_alloc_op_queue(OP_MKNOD, dir_inode);
	if (!op) {
		return -ENOMEM;
	}

	op->dentry = entry;
	op->mknod.mode = mode;
	op->stat = &st;

	ret = xfs_wait_op_queue_complete(md, op, md->q_tmo);

	if (ret != 0) {
		printk("xfs_mknod: dir_ino=%ld, name=[%s], mode=%d\n", dir_inode->i_ino, entry->d_name.name, mode );
		return ret; 
	}

	/////
	inode = xfs_iget(dir_inode->i_sb, &st);
	if (!inode) {
		return -ENOMEM;
	}

	d_instantiate(entry, inode); ///entry 和 inode关联
	///
	xfs_dentry_invalidate(entry); //修改超时
	xfs_attr_invalidate(inode); ////inode 属性重新从用户空间查询
	xfs_attr_invalidate(dir_inode); ////inode 属性重新从用户空间查询

	return 0;
}
static int xfs_create(struct inode *dir_inode, struct dentry *entry, umode_t mode, bool excl)
{
	return xfs_mknod(dir_inode, entry, mode, 0);
}
static int xfs_mkdir(struct inode *dir_inode, struct dentry *entry, umode_t mode)
{
	return xfs_mknod(dir_inode, entry, (mode|S_IFDIR), 0);
}

/////
static int xfs_rmnod(struct inode* dir_inode, struct dentry* dentry, int is_rmdir )
{
	////
	struct mon_dir_t* md;
	struct op_queue_t* op;
	int ret;

	if (!dir_inode || is_bad_inode(dir_inode)) {
		return -EIO;
	}
	md = I_MON_DIR(dir_inode);

	op = xfs_alloc_op_queue(OP_RMNOD, dir_inode);
	if (!op) {
		return -ENOMEM;
	}
	
	op->dentry = dentry;
	op->rmnod.is_rmdir = is_rmdir;

	ret = xfs_wait_op_queue_complete(md, op, md->q_tmo);

	if (ret != 0) {
		printk("xfs_rmnod: is_rmdir=%d, dir_ino=%ld, name=[%s] err=%d\n", is_rmdir, dir_inode->i_ino, dentry->d_name.name, ret );
		return ret;
	}

	////
	if (dentry->d_inode) {
		///
		if (is_rmdir) {
			clear_nlink(dentry->d_inode);
		}
		else{
			drop_nlink(dentry->d_inode);
		}
		//////

		xfs_attr_invalidate(dentry->d_inode); ////inode 属性重新从用户空间查询
	}

	xfs_dentry_invalidate(dentry); //修改超时,重新 lookup
	xfs_attr_invalidate(dir_inode); ////inode 属性重新从用户空间查询
	//////
	return 0;
}
static int xfs_rmdir(struct inode* dir_inode, struct dentry* dentry)
{
	return xfs_rmnod(dir_inode, dentry, 1 );
}
static int xfs_unlink(struct inode* dir_inode, struct dentry* dentry)
{
	return xfs_rmnod(dir_inode, dentry, 0 );
}

/////
static int xfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	                  struct inode *new_dir, struct dentry *new_dentry)
{
	struct op_queue_t* op;
	struct mon_dir_t* md;
	int ret;
	if (!old_dir || is_bad_inode(old_dir)) {
		return -EIO;
	}
	if (!new_dir || is_bad_inode(new_dir)) {
		return -EIO;
	}
	md = I_MON_DIR(old_dir);

	op = xfs_alloc_op_queue(OP_RENAME, old_dir);
	if (!op) {
		return -ENOMEM;
	}

	op->dentry = old_dentry;
	op->rename.new_dir = new_dir;
	op->rename.new_dentry = new_dentry;

	ret = xfs_wait_op_queue_complete(md, op, md->q_tmo);

	if (ret != 0) {
		printk("xfs_rename: olddir_ino=%ld, old_name[%s] -> newdir_ino=%ld, new_name=[%s]; ret=%d\n", 
			old_dir->i_ino, old_dentry->d_name.name, new_dir->i_ino, new_dentry->d_name.name, ret );
		///
		return ret;
	}

	////
	xfs_dentry_invalidate(old_dentry ); ////
	xfs_dentry_invalidate(new_dentry ); ////

	xfs_attr_invalidate(old_dir); ////inode 属性重新从用户空间查询
	xfs_attr_invalidate(new_dir); ////inode 属性重新从用户空间查询
	if(old_dentry->d_inode) xfs_attr_invalidate(old_dentry->d_inode); ////inode 属性重新从用户空间查询
	if(new_dentry->d_inode) xfs_attr_invalidate(new_dentry->d_inode); ////inode 属性重新从用户空间查询

	return 0;
}

/////////////// 
const struct file_operations xfs_dir_fops =
{
	.read = generic_read_dir,
	.readdir = xfs_readdir,
	.open = xfs_dir_open,
	.release = xfs_dir_release,
};

const struct inode_operations xfs_dir_iops =
{
	.create = xfs_create,
	.mknod =  xfs_mknod,
	.mkdir =  xfs_mkdir,
	.lookup = xfs_lookup,
	.unlink = xfs_unlink,
	.rmdir =  xfs_rmdir,
	.rename =  xfs_rename,
	.getattr = xfs_getattr,
	.setattr = xfs_setattr,
};


