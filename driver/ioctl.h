////By fanxiushu 2016-07-29

#pragma once


struct ioctl_mondir_t
{
	char        mon_dir[256];
	///
	uint64_t    root_ino; ///
	uint32_t    root_uid;
	uint32_t    root_gid;

	///超时，单位毫秒
	uint32_t    query_tmo; // msec
	uint32_t    trans_tmo; // msec
	/////
	uint32_t    entry_tmo; // msec
	uint32_t    attr_tmo;  // msec
	int32_t     is_direct_io; //是否直接读写
};

#define IOCTL_MAGIC                   'X'
#define IOCTL_SET_MON_DIR             _IO(IOCTL_MAGIC, 0)   /// ioctl code
#define IOCTL_POLL_NOWAIT             _IO(IOCTL_MAGIC, 1)   /// select或者poll调用立马返回
#define IOCTL_CLEAR_INODE_USRCTX      _IO(IOCTL_MAGIC, 2)   /// 清空inode的 usrctx

////
#define OP_LOOKUP                  1                 //lookup，实际也是查询属性，不过给出的是parent的ino，和子文件名
#define OP_QUERY_STAT              2                 //查询属性
#define OP_SET_STAT                3                 //设置属性
#define OP_READDIR                 4                 //读取目录内的子文件或子目录
#define OP_MKNOD                   5                 //创建文件或者目录
#define OP_RMNOD                   6                 //删除文件或目录
#define OP_RENAME                  7                 //重命名
#define OP_READ                    8                 //读
#define OP_WRITE                   9                 //写

//////
#define SET_ATTR_MODE	           (1 << 0)    // chmod
#define SET_ATTR_UID	           (1 << 1)    // chown
#define SET_ATTR_GID	           (1 << 2)    // chown
#define SET_ATTR_SIZE	           (1 << 3)    // truncate
#define SET_ATTR_ATIME	           (1 << 4)    // utimes
#define SET_ATTR_MTIME	           (1 << 5)
#define SET_ATTR_CTIME	           (1 << 6)

///文件信息，从用户层获取
struct file_stat_t
{
	uint64_t          ino;       ///设备节点号, 应用层生成
	uint32_t          flags;     ///
	uint32_t          padding;   ///
	uint32_t          mode;      /// S_IFDIR, S_IFREG 等
	uint32_t          uid;       /// user id
	uint32_t          gid;       /// group id
	uint32_t          nlink;     /// hard link, set to 1 ,not used 
								 /////
	uint64_t          size;
	uint64_t          blocks;    ///
	uint64_t          atime;
	uint64_t          mtime;
	uint64_t          ctime;

};

struct file_dirfill_t
{
	uint64_t         ino;   ////
	uint32_t         type;  ////DT_REG, DT_DIR 等
	int32_t          name_len; ////
	char             name[256]; ////
};
////
struct ioctl_oparg_t
{
	uint64_t       inter_handle;
	uint64_t       inter_seqno;

	//////
	uint32_t       op_type;    ////
	
	uint32_t       user_pid;      ////用户层保存的指针和进程ID，每个i_ino对应一个 i_usrctx
	uint64_t       i_ino;         ////节点number
	uint64_t       i_usrctx;  ////
	uint64_t       i_usrctx2; ////

	union {
		////
		struct {
			uint64_t              d_id;       //唯一id，因为opendir打开之后才能readdir，所以这个标志用来区分不同的opendir调用。
			uint64_t              d_usrctx;   ///
			uint64_t              d_usrctx2;  ///
			int32_t               is_end;     ///
		}readdir;
		/////
		struct {
			uint32_t              mode;  ///创建 文件或目录的mode  
		}mknod;
		struct {
			int32_t              is_rmdir; ///如果is_dir为真是 rmdir， 否则unlink
		}rmnod;
		////
		struct {
			uint64_t              newdir_ino; ///新目录的ino
		}rename;
		/////
		struct {
			uint64_t              offset; 
			uint32_t              length;
		}readwrite;
		/////
	};

	/////
	int32_t        ret;    //返回结果,0成功，<0 错误码

	uint32_t       length; //后边的数据长度
};

