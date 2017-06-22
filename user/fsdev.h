///By fanxiushu 2016-08-12

#pragma once

struct xfs_mount_t
{
	uint64_t     root_ino;
	unsigned int root_uid;
	unsigned int root_gid;
	//// 超时，单位都是毫秒
	uint32_t     query_tmo;
	uint32_t     trans_tmo;

	uint32_t     entry_tmo;
	uint32_t     attr_tmo; 
	int32_t      is_direct_io; ///
};

#define LOOKUP                1
#define QUERY_STAT            2
#define SET_STAT              3
#define READDIR               4
#define MKNOD                 5
#define RMNOD                 6
#define RENAME                7                 //重命名
#define READ                  8                 //读
#define WRITE                 9                 //写

struct stat_t
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
	uint64_t          blocks;    /////
	uint64_t          atime;
	uint64_t          mtime;
	uint64_t          ctime;

};

struct dirfill_t
{
	uint64_t         ino;   ////
	uint32_t         type;  ////DT_REG, DT_DIR 等
	int32_t          name_len; ////
	char             name[256]; ////
};

struct fsdev_request_t
{
	int           type;

	uint64_t      ino; 

	void*         i_usrctx;
	void*         i_usrctx2;

	union {
		struct {
			const char* sub_name; ///
			struct stat_t st;
		}stat;
		/////
		struct {
			uint64_t          d_id;
			void*             d_usrctx;
			void*             d_usrctx2; ///
			struct dirfill_t* fill;
			int               is_end;
		}readdir;
		///
		struct {
			int               mode;
			const char*       name;
			struct stat_t     st;
		}mknod;
		struct {
			int               is_rmdir; /// is_dir!=0 is rmdir, else unlink
			const char*       name;
		}rmnod;
		struct {
			uint64_t          newdir_ino;
			const char*       old_name;
			const char*       new_name;
		}rename;
		struct {
			uint64_t         offset;
			int32_t          length;
			char*            buffer; 
		}readwrite;
	};
	//////
	int   ret;

	int   length;
	///
};

////low function 
void* fsdev_mount(const char* mon_dir, struct xfs_mount_t* mnt);
int fsdev_umount(void* handle);
int fsdev_wakeup(void* handle);
int fsdev_clear_inode_usrctx(void* handle, uint64_t ino);

fsdev_request_t* fsdev_begin_request(void* handle);
int fsdev_end_request(void* handle, struct fsdev_request_t* req);

////////
struct read_dir_t
{
	uint64_t       d_id;
	void*          d_usrctx;
	void*          d_usrctx2;
	bool           is_end;
	///填充的内容
	char*          name;
	bool           is_stat; //是否获取到 文件 信息
	struct stat_t  stat;
};

struct fsdev_mon_dir_t
{
	const char*         mon_dir;
	int                 thread_cnt;
	///超时，单位毫秒
	int                 query_timeout; //查询超时
	int                 trans_timeout; //读写超时
	int                 entry_timeout; //目录结构缓存超时
	int                 attr_timeout;  //属性缓存超时
	int                 is_direct_io;  //采用直接读写方式
	int                 is_gbk_path;   //路径名是否转成 GB2312

	int                 root_uid;
	int                 root_gid;
	void*               param;

	////callback
	int  (*stat)(const char* path, struct stat_t* st , void* param );
	int  (*readdir)(const char* path, struct read_dir_t* item, void* param );
	int  (*chmod)(const char* path, int mode, void* param);
	int  (*chown)(const char* path, int uid, int gid, void* param);
	int  (*utime)(const char* path, time_t atime, time_t mtime, void* param);
	int  (*truncate)(const char* path, int64_t newsize, void* param);
	int  (*mknod)(const char* path, int mode, void* param);
	int  (*mkdir)(const char* path, int mode, void* param);
	int  (*rmdir)(const char* path, void* param);
	int  (*unlink)(const char* path, void* param);
	int  (*rename)(const char* old_path, const char* new_path, void* param);
	int  (*read)(const char* path, char* buffer, int64_t offset, int length, void* param);
	int  (*write)(const char* path, char* buffer, int64_t offset, int length, void* param);

};

///high function
void* fsdev_mon_dir_create(struct fsdev_mon_dir_t* fs);
int   fsdev_mon_dir_close(void* handle);

