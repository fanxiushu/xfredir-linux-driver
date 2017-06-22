/// by fanxiushu 2016-07-28
#include "xfs_redir.h"

///
struct xfs_t    __global_xfs;

/////

int xfs_init(void )
{
	xfs->cdo_major = 0;
	xfs->cdo_cls = NULL;
	xfs->seq_no = 0;
	INIT_LIST_HEAD(&xfs->mon_dirs); 

	///
	mutex_init(&xfs->mtx); //// init global lock 

	xfs->inode_pool = kmem_cache_create("xfs_redir_inode_cache",
		sizeof(struct xfs_inode_t),
		0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),	
		NULL );

	if (xfs->inode_pool == NULL) {
		return -ENOMEM;
	}

	///
	xfs->op_pool = kmem_cache_create("xfs_redir_op_cache",
		sizeof(struct op_queue_t),
		0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
		
	if (!xfs->op_pool) {
		kmem_cache_destroy(xfs->inode_pool);
		xfs->inode_pool = NULL;
		return -ENOMEM;
	}

	////

	return 0;
}

void xfs_deinit(void)
{
	if (xfs->inode_pool) {
		kmem_cache_destroy(xfs->inode_pool);
	}
	if (xfs->op_pool) {
		kmem_cache_destroy(xfs->op_pool);
	}
	/////
}

struct op_queue_t* xfs_alloc_op_queue(int op_type, struct inode* op_inode )
{
	struct op_queue_t* op = (struct op_queue_t*)kmem_cache_alloc(xfs->op_pool, GFP_KERNEL);
	if (!op) return NULL;
	/////
	init_waitqueue_head(&op->wq);
	INIT_LIST_HEAD(&op->list); ///
	op->op_type = op_type;
	op->inode = op_inode;
	op->ret = -1;
	op->is_complete = 0;
	op->is_noreply = 0; 
	op->is_nobuffer = 0; 
	op->is_clear_inode_usrctx = 0; 
	op->readwrite.pages = NULL; ///
	op->readwrite.buffer = NULL;

	return op;
}
void xfs_free_op_queue(struct op_queue_t* op)
{
	if (op) {
		kmem_cache_free(xfs->op_pool, op);
	}
	///////

}
int xfs_wait_op_queue_complete(struct mon_dir_t* md, 
	struct op_queue_t* op , long tmo_jiffies ) // timeout is jiffies
{
	int ret; ////

	op->is_complete = 0;

	lock();
	///
	if (!md->is_valid) { //监控目录已经无效了
		printk("monitor director not valid. \n");
		xfs_free_op_queue(op);
		///
		unlock(); ///

		return -ENOENT;
	}
	///
	list_add_tail(&op->list, &md->wait_head); /// 加入到等待处理队列

	wake_up_interruptible(&md->wait_q); //通知用户进程，有新的请求

	unlock();

	/////
	ret = wait_event_interruptible_timeout( op->wq, op->is_complete!=0 , tmo_jiffies); //等待用户层完成或者超时

	lock();
	list_del(&op->list); ////可能已经在 __op_queue_complete 中被移除出队列，但是已经INIT_LIST_HEAD，所以这里再次list_del不会出问题
	INIT_LIST_HEAD(&op->list);
	unlock();

	////////
	if (ret == 0) {// time out
		ret = -ETIME;
	}
	if (ret < 0) {
		///
		xfs_free_op_queue(op);
		return ret;
	}

	////
	if (op->is_complete) {
		///
		ret = op->ret;
	}
	else{
		ret = -ETIME;
	}

	xfs_free_op_queue(op);
	//////
	return ret;
}

////
int create_monitor_directory(const char* mon_dir, struct mon_dir_t** p_dir)
{
	struct mon_dir_t* md = NULL;
	struct mon_dir_t* md_p;
	int sz;

	lock();

	list_for_each_entry(md_p, &xfs->mon_dirs, list) {
		///
		if (strcmp(mon_dir, md_p->path.buffer) == 0) { ////从全局链表检测是否已经创建了监控目录
			md = md_p;
			break;
		}
	}
	if (md) {
		unlock();
		return -EEXIST; ///
	}

	/////
	sz = sizeof(struct mon_dir_t) + strlen(mon_dir) + 1;

	md = (struct mon_dir_t*)kzalloc( sz, GFP_KERNEL); // malloc and memset zero
	if (!md) {
		unlock();
		///
		return -ENOMEM;
	}
	///初始化 mon_dir_t
	md->path.buffer = (char*)md + sizeof(struct mon_dir_t);
	md->path.max_length = md->path.length = sz - sizeof(struct mon_dir_t) - 1; 
	strcpy(md->path.buffer, mon_dir); 

	md->is_valid = 1;
	md->ref_count = 1; // ref count = 1
	
	INIT_LIST_HEAD(&md->wait_head);
	INIT_LIST_HEAD(&md->busy_head);
	init_waitqueue_head(&md->wait_q); 

	md->root_uid = md->root_gid = 1; /// default 
	//
	//////

	list_add_tail(&md->list, &xfs->mon_dirs); //添加到全局队列

	unlock();

	*p_dir = md; ////

	return 0;
}

///
void destroy_monitor_directory(struct mon_dir_t* dir)
{
	struct op_queue_t* op;
	int ret = -EINVAL;
	struct list_head* entry;

	if (!dir)return;
	///
	lock();

	dir->is_valid = 0; ////

	while (!list_empty(&dir->busy_head)) {
		entry = dir->busy_head.next;
		op = list_entry(entry, struct op_queue_t, list);
		////
		__op_queue_complete(op, ret); ////
	}

	//// complete wait op_queue_t
	while (!list_empty(&dir->wait_head)) {
		entry = dir->wait_head.next;
		op = list_entry(entry, struct op_queue_t, list);
		////
		__op_queue_complete(op, ret); ////
	}

	///移除出xfs->mon_dirs队列
	list_del(&dir->list);
	INIT_LIST_HEAD(&dir->list); 

	////
	__mon_dir_release( dir );

	unlock();
}

int xfs_clear_inode_usrctx(struct mon_dir_t* md, u64 ino)
{
	struct inode* inode;
	struct xfs_inode_t* xi;
	struct op_queue_t* op;
	lock();
	if (!md->sb) {
		unlock();
		return -EINVAL;
	}
	///
	inode = xfs_ifind(md->sb, ino);
	if (!inode) {
		unlock();
		return -ENOENT;
	}
	xi = XFS_INODE(inode);

	xi->user_pid = 0;
	xi->i_usrctx = xi->i_usrctx2 = 0; 

	list_for_each_entry(op, &md->busy_head, list) {
		if (op->inode == inode) {
			op->is_clear_inode_usrctx = 1; ///
		}
		////
	}

	iput(inode);
	////
	unlock();
	return 0;
}

/////

static int __init init_xfs_redir(void)
{
	int err;

	/// init global val
	err = xfs_init();
	if (err) {
		printk("--- xfs_init err=%d\n", err);
		return err;
	}

	/// init cdev for userspace
	err = cdo_init();
	if (err) {
		xfs_deinit();
		///
		printk("--- cdo_init err=%d\n", err);
		return err;
	}

	/////register filesystem
	err = xfs_reg_fs();
	if (err) {
		cdo_deinit();
		xfs_deinit();
		printk("--- xfs_reg_fs err=%d\n", err );
		return err;
	}

	/////
	return 0;

}

static void __exit exit_xfs_redir(void)
{
	xfs_unreg_fs(); //注销文件系统

	cdo_deinit();   //注销字符设备

	xfs_deinit();   //取消全局变量
	/////
}


module_init(init_xfs_redir)

module_exit(exit_xfs_redir)

MODULE_LICENSE("GPL");

