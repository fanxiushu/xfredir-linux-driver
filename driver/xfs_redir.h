///// By fanxiushu 2016-07-28
#pragma once

#include "common.h"
#include "ioctl.h"

#define INV_INODE_ID    0
#define ROOT_INODE_ID   1  //根目录的ID，

#define XFS_SB_MAGIC    0x2390da02   ///
#define XFS_FILE_TYPE   "xfs_redir"  /// 文件系统名字
////
#define XFS_MAX_DIO_PAGES_COUNT          128  ////一次请求最大的页面数

struct xfs_t
{
	////
	struct mutex        mtx;
	
	/// user cdev
	int                 cdo_major;
	struct  cdev        cdo_dev;
	struct  class*      cdo_cls;

	struct kmem_cache*  inode_pool;
	struct kmem_cache*  op_pool;    //操作内存
	
	struct list_head    mon_dirs; /// -> mon_dir_t 

	u64                 seq_no;   ///
};

extern struct xfs_t __global_xfs;
#define  xfs        (&__global_xfs)

#define lock()      mutex_lock(&xfs->mtx);
#define unlock()    mutex_unlock(&xfs->mtx);

////


struct xfs_inode_t
{
	////
	struct inode         vfs_inode;  ///
	u64                  i_no;       /// inode number

	u64                  i_attr_time; //// 属性的有效时间, jiffies方式表达

	atomic_t             open_count;  //作为文件打开的个数
	/////
	u32                  user_pid;      //操作以下两个指针的进程ID
	u64                  i_usrctx;
	u64                  i_usrctx2; //单纯保存跟inode相关的用户层指针

};

////在打开文件或者目录的私有结构
struct xfs_file_t
{
	unsigned char   is_dir;
	unsigned char   is_readdir;

	///
	u64             d_usrctx;  ///
	u64             d_usrctx2; ///

};

/////
struct mon_dir_t
{
	struct list_head      list;      /// --> xfs_t.mon_dirs;
	
	unsigned char         is_valid;  //  是否有效，
	unsigned char         is_poll_nowait; ///
	long                  ref_count; //  引用计数

	struct string_t       path;      /// 监控的完整路径,格式 /home/mon_dir , /root/path2
	///
	struct list_head      wait_head; /// 等待队列，指向 op_queue_t 

	struct list_head      busy_head; /// 忙碌队列，指向 op_queue_t 

	////
	wait_queue_head_t     wait_q;

	struct super_block*   sb;
	///////////////
	u64                   root_ino; ///根目录 / 的 ino 
	u32                   root_uid;
	u32                   root_gid; ///根目录的uid和gid

	/////
	u32                   q_tmo; //查询超时, 单位jiffies
	u32                   t_tmo; //传输超时，单位jiffies
	//////
    u32                   e_tmo;  //entry的超时时间,单位jiffies
	u32                   a_tmo;  //属性的超时时间, 单位jiffies
	int                   is_dio; ///直接IO
};

struct dio_page_t       //直接读写的page参数
{
	size_t          length; /// 读写长度
	loff_t          offset; ///
	////
	int             is_modify_page; ///页可修改
	unsigned int    pg_off; /// 相对于页的偏移，用户空间的地址并不是页对齐
	int             npages;
	struct page**   pages;
};
struct op_queue_t
{
	struct list_head    list; //// -> mon_dir_t.wait_head or mon_dir_t.busy_head 
	
	/////
	wait_queue_head_t   wq; 

	int                 op_type; ///操作类型

	unsigned char       is_complete; //  是否完成
	unsigned char       is_noreply;  //  不需要从用户层返回数据
	unsigned char       is_nobuffer; //  IOCTL处理时候，用户层提供的空间不够
	unsigned char       is_clear_inode_usrctx; ///是否发送清除usrctx的命令
	int                 ret;         /// 返回码

	/////
	u64                 inter_seqno; ///

	struct inode*       inode;    /// 操作的inode
	struct dentry*      dentry;   /// 操作的dentry
	struct file_stat_t* stat;     /// 操作的属性
	////
	union {
		
		////
		struct {
			struct file_dirfill_t*   fill;   ////
			struct xfs_file_t*       fp;     /////
		}readdir;
		///
		struct {
			umode_t                  mode;
		}mknod;
		struct {
			int                      is_rmdir; /// rmdir or unlink
		}rmnod;
		struct {
			struct inode*            new_dir;
			struct dentry*           new_dentry;
		}rename;
		////
		struct {
			loff_t                   offset;
			size_t                   length; 
			char*                    buffer; 
			struct dio_page_t*       pages;   //如果是直接读写page
		}readwrite;
		/////
	};

};

///
static inline void __mon_dir_addref(struct mon_dir_t* dir)
{
	++dir->ref_count;
}
static inline void __mon_dir_release(struct mon_dir_t* dir )
{
	////
	if (--dir->ref_count == 0 ) { //销毁mon_dir_t ， 释放内存
		///
		printk("#### mon_dir_release [%s]\n", dir->path.buffer );

		kfree(dir); ///
		/////
	}
}

static inline void __op_queue_complete(struct op_queue_t* op, int ret)
{
	list_del(&op->list);
	INIT_LIST_HEAD(&op->list); //初始化为空，防止再次list_del时候崩溃

	op->is_complete = 1; //complete
	op->ret = ret; // ret

	wake_up_interruptible(&op->wq); ///
	///
}

static inline struct xfs_inode_t* XFS_INODE(struct inode* in)
{
	return container_of(in, struct xfs_inode_t, vfs_inode);
}

static inline struct mon_dir_t* MON_DIR(struct super_block* sb)
{
	return (struct mon_dir_t*)sb->s_fs_info; 
}
static inline struct mon_dir_t* I_MON_DIR(struct inode* inode)
{
	if (!inode)return NULL;
	return (struct mon_dir_t*)inode->i_sb->s_fs_info;
}

////
#if BITS_PER_LONG >= 64
static inline void xfs_dentry_settime(struct dentry *entry, u64 time){
	entry->d_time = time;
}
static inline u64 xfs_dentry_time(struct dentry *entry){
	return entry->d_time;
}
#else //32位系统
static inline void xfs_dentry_settime(struct dentry *entry, u64 time){
	entry->d_time = time;
	entry->d_fsdata = (void *)(unsigned long)(time >> 32);
}
static inline u64 xfs_dentry_time(struct dentry *entry){
	return (u64)entry->d_time +
		((u64)(unsigned long)entry->d_fsdata << 32);
}
#endif
static inline u64 xfs_attr_time(struct inode* inode){
	return XFS_INODE(inode)->i_attr_time; ///
}
static inline void xfs_dentry_change_timeout(struct dentry* entry, long tmo_jiffies){
	if (tmo_jiffies <= 0) xfs_dentry_settime( entry, 0 );
	else xfs_dentry_settime(entry, get_jiffies_64() + tmo_jiffies); ///
}
static inline void xfs_attr_change_timeout(struct inode* inode, long tmo_jiffies){
	if (tmo_jiffies <= 0) XFS_INODE(inode)->i_attr_time = 0;
	else XFS_INODE(inode)->i_attr_time = get_jiffies_64() + tmo_jiffies;///
}
#define xfs_dentry_invalidate(dentry)  xfs_dentry_change_timeout(dentry,0);
#define xfs_attr_invalidate(inode)     xfs_attr_change_timeout(inode, 0);


///文件或目录的操作函数
extern const struct file_operations  xfs_dir_fops;
extern const struct inode_operations xfs_dir_iops;

extern const struct address_space_operations xfs_file_aops;
extern const struct file_operations  xfs_file_fops;
extern const struct inode_operations xfs_file_iops;

extern const struct dentry_operations xfs_dentry_operations;

////// function

int  cdo_init(void);
void cdo_deinit(void);

int  xfs_reg_fs(void);
void xfs_unreg_fs(void);

int  create_monitor_directory(const char* mon_dir, struct mon_dir_t** p_dir);
void destroy_monitor_directory(struct mon_dir_t* dir);

void xfs_set_inode_stat(struct inode* inode, struct file_stat_t* fattr);
struct inode* xfs_iget(struct super_block* sb, struct file_stat_t* attr);
struct inode* xfs_ifind(struct super_block *sb, u64 ino);

struct op_queue_t* xfs_alloc_op_queue(int op_type, struct inode* op_inode);
int xfs_wait_op_queue_complete(struct mon_dir_t* md,
	struct op_queue_t* op, long timeout); // timeout is second
	
int xfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat);
int xfs_setattr(struct dentry *dentry, struct iattr *attr);
void xfs_update_inode_size(struct inode* inode, loff_t newsize);

//直接读写时候，实现pages和user_buffer复制数据
size_t xfs_copy_user_with_pages(struct dio_page_t* pgs, char __user* user_buffer,
	size_t user_length, int is_to_user);

int xfs_clear_inode_usrctx(struct mon_dir_t* md, u64 ino);

