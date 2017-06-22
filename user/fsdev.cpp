/////
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mount.h>
#include <pthread.h>
#include <iconv.h>
#include <list>
#include <string>
#include <map>
#include <sstream>
using namespace std;

#define msleep(m) {struct timespec t;t.tv_sec=m/1000;t.tv_nsec=(m%1000)*1000000; nanosleep(&t,NULL);}
#define atomic_inc(x)  __sync_add_and_fetch((x),1)  
#define atomic_dec(x)  __sync_sub_and_fetch((x),1) 

#include "fsdev.h"

///
#include "../driver/ioctl.h"

#define  lock(k)  pthread_mutex_lock(&(k));
#define  unlock(k) pthread_mutex_unlock(&(k));
#define  XFS_ROOT_ID   1 //根目录 '/' 的ino

///获取毫秒时间，1970开始
static int64_t time_msec()
{
	int64_t t = 0;
	struct timespec ts = { 0 };
	clock_gettime(CLOCK_REALTIME, &ts);

	t = (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / (1000 * 1000);
	return t; 
}

struct inode_info_cache
{
	const char*    paths[20];

	int64_t        last_update_time; //最后一次更新 stat_t, 单位毫秒
	struct stat_t  st;
};
// 缓存 ino 和文件路径的关系以及对应的stat信息， 此处缓存有个缺陷，只添加没删除，所以如果非常多的文件目录缓存的话，浪费的内存很大
struct name_inode_cache
{
	pthread_mutex_t  lck;

	uint32_t         inode_number;
	bool             ino_reapet;

	map<string, uint32_t>      path_ids; ///完整路径和ino关联
	map<uint32_t, inode_info_cache> id_paths; ///

	name_inode_cache() {
		pthread_mutex_init(&lck, NULL);
		inode_number = XFS_ROOT_ID + 1; ///
		ino_reapet = false;
	}
	~name_inode_cache() {
		pthread_mutex_destroy(&lck);
	}
	//////
	void unlocked() { unlock(lck); }
	uint32_t find_inode_number(const char* path, bool create_if_not_exists ) {
		///
		if ( strcmp(path,"/") == 0 ) return XFS_ROOT_ID; ///root id
		////
		uint32_t ino = 0;
		lock(lck);
		map<string, uint32_t>::iterator it = path_ids.find(path); 
		if (it != path_ids.end()) {
			ino = it->second; // found
		}
		else if (create_if_not_exists) {
			uint32_t no = inode_number++;
			if (inode_number <= XFS_ROOT_ID) {
				ino_reapet = true; 
				inode_number = XFS_ROOT_ID + 1;
			}
			if (ino_reapet) {
				while (1) {
					map<uint32_t, inode_info_cache>::iterator kk;
					kk = id_paths.find(no); if (kk == id_paths.end())break;
					++no;
				}
			}

			path_ids[path] = no; 
			it = path_ids.find(path);

			inode_info_cache iic; 
			iic.paths[0] = it->first.c_str();
			iic.last_update_time = 0;
			id_paths[no] = iic; 
			////
			ino = no; ////
		}
		unlock(lck);
		return ino; 
	}
	int find_inode_stat(const char* path, struct stat_t* st, int64_t tmo) { //单位毫秒
		int r = -1;
		if (tmo <= 0) return -1;
		lock(lck);
		map<string, uint32_t>::iterator it = path_ids.find(path);
		if (it != path_ids.end()) {
			uint32_t ino = it->second;
			map<uint32_t, inode_info_cache>::iterator kk = id_paths.find(ino);
			if (kk != id_paths.end()) {
				inode_info_cache* iic = &kk->second;
				int64_t cur = time_msec();
				if (abs(cur - iic->last_update_time) < tmo) {
					*st = iic->st;
					r = 0;
				}
			}
		}
		unlock(lck);
		return r;
	}
	int update_inode_stat(uint32_t ino, struct stat_t* st ) {
		int r = -1;
		lock(lck);
		map<uint32_t, inode_info_cache>::iterator it = id_paths.find(ino);
		if (it != id_paths.end()) {
			inode_info_cache* iic = &it->second;
			r = 0;
			iic->last_update_time = time_msec();
			iic->st = *st;
		}
		unlock(lck);
		return r;
	}
	int invalid_inode_stat(uint32_t ino) {
		int r = -1;
		lock(lck);
		map<uint32_t, inode_info_cache>::iterator it = id_paths.find(ino);
		if (it != id_paths.end()) {
			inode_info_cache* iic = &it->second;
			r = 0;
			iic->last_update_time = 0;
		}
		unlock(lck);
		return r;
	}
	const char* find_path_locked(uint32_t ino) {
		lock(lck);
		if (ino == XFS_ROOT_ID) return "/";
		map<uint32_t, inode_info_cache>::iterator it = id_paths.find(ino);
		if (it == id_paths.end()) {
			unlock(lck);
			return NULL;
		}
		return it->second.paths[0];
	}

};


struct _fsdev_t
{
	int      fd;  ////
	int      wait_tmo; /// 
	char     mon_dir[256]; ///
};

uint64_t _get_sys_umount_address()
{
	uint64_t addr = 0;
	FILE* fp = fopen("/proc/kallsyms", "r");
	if (!fp) {
		printf("open /proc/kallsysm err=%d\n",errno);
		return 0;
	}
	char buf[8192];
	while (!feof(fp)) {
		buf[0]=0;
		if (!fgets(buf, sizeof(buf), fp))break; 
		///
		if (strstr(buf, "sys_umount")) { // 
			char* end;
			addr = strtoull(buf, &end, 16); 
		//	printf("[%s] addr=%lld\n", buf, addr);///
			break;
		}
		/////
	}
	fclose(fp);
	return addr;
}
void* fsdev_mount(const char* mon_dir, struct xfs_mount_t* mnt )
{
	int fd = open("/dev/xfsredir", O_RDWR);
	if (fd < 0) {
		printf("fsdev_mount: open device err=%d\n", errno );
		return NULL;
	}

	struct ioctl_mondir_t md; 
	memset(&md, 0, sizeof(md));
	strcpy(md.mon_dir, mon_dir);
	md.root_uid = mnt->root_uid;
	md.root_gid = mnt->root_gid;
	md.root_ino = mnt->root_ino;
	md.query_tmo = mnt->query_tmo;
	md.trans_tmo = mnt->trans_tmo;
	md.entry_tmo = mnt->entry_tmo;
	md.attr_tmo = mnt->attr_tmo;
	md.is_direct_io = mnt->is_direct_io;

	////
	int r = ioctl(fd, IOCTL_SET_MON_DIR, &md);
	if (r < 0) {
		printf("fsdev_mount: set monitor directory [%s] err=%d\n", mon_dir, errno );
		close(fd);
		return NULL;
	}
	/////
	r = mount("none", mon_dir, "xfs_redir", 0 , mon_dir );
	if (r < 0) {
		printf("fsdev_mount: mount [%s] err=%d\n", mon_dir, errno);
		close(fd);
		return NULL;
	}
	///
	r = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); // set nonblock 
	if (r < 0) printf("fcntl: O_NONBLOCK err=%d\n", errno );
	////

	_fsdev_t* dev = new _fsdev_t;
	dev->fd = fd;
	dev->wait_tmo = 15; ///
	strcpy(dev->mon_dir, mon_dir);

	return dev;
}

int fsdev_umount(void* handle)
{
	_fsdev_t* dev = (_fsdev_t*)handle;
	if (!dev) return -1;
	/////
	close(dev->fd);
	int r = umount(dev->mon_dir);
	if (r < 0) {
		printf("fsdev_unmount: unmount [%s] err=%d\n", dev->mon_dir, errno);
	}

	delete dev;
	return 0;
}

int fsdev_wakeup(void* handle)
{
	_fsdev_t* dev = (_fsdev_t*)handle;
	if (!dev) return -1;

	int r = ioctl(dev->fd, IOCTL_POLL_NOWAIT, 0);
	if (r < 0) {
		printf("fsdev_wakeup: IOCTL_POLL_NOWAIT err=%d\n", errno );
	}
	return r;
}

int fsdev_clear_inode_usrctx(void* handle, uint64_t ino)
{
	_fsdev_t* dev = (_fsdev_t*)handle;
	if (!dev) return -1;

	int r = ioctl(dev->fd, IOCTL_CLEAR_INODE_USRCTX, &ino);
	if (r < 0) {
		printf("fsdev_clear_inode_usrctx: ino=%lld, err=%d\n", ino, errno );
	}
	return r;
}

fsdev_request_t* fsdev_begin_request(void* handle)
{
	_fsdev_t* dev = (_fsdev_t*)handle;
	if (!dev)return NULL;
	void* buf;
	int buf_size = 64 * 1024;
	fsdev_request_t* req;
	ioctl_oparg_t* ctl;
	char* data;
	int ret;

	while (true) {	

		struct pollfd ufds;
		ufds.fd = dev->fd; ufds.events = POLLIN; ufds.revents = 0;
		int ms = dev->wait_tmo*1000; // msecond
		int status = poll(&ufds, 1, ms);
		if (status <= 0) {
//			printf("fsdev_begin_request wait timeout\n");
			return NULL;
		}

		buf = malloc(buf_size + sizeof(fsdev_request_t)* 2 );
		if (!buf)return NULL;
		req = (fsdev_request_t*)buf;
		ctl = (ioctl_oparg_t*)((char*)buf + sizeof(fsdev_request_t));
		data = (char*)((char*)ctl + sizeof(ioctl_oparg_t));

		ret = read(dev->fd, ctl, buf_size);
		if (ret < sizeof(ioctl_oparg_t)) {
			free(buf);
			printf("fsdev_begin_request: read ret=%d,err=%d\n", ret, errno );
			return NULL;
		}
		if (ctl->length + sizeof(ioctl_oparg_t) > buf_size) { //缓存大小跟实际需要读取的数据有差距
			printf("fsdev_begin_request: buffer too small.\n");
			buf_size = ctl->length + sizeof(ioctl_oparg_t) + 16 * 1024;
			free(buf); ///
			continue;
		}
		/////
		if (ctl->op_type == OP_READ && ( sizeof(ioctl_oparg_t) + ctl->readwrite.length ) > buf_size ) { //读

			///
			buf_size = sizeof(ioctl_oparg_t) + ctl->readwrite.length + 16 * 1024;
			buf = realloc(buf, buf_size);
			///
			req = (fsdev_request_t*)buf;
			ctl = (ioctl_oparg_t*)((char*)buf + sizeof(fsdev_request_t));
			data = (char*)((char*)ctl + sizeof(ioctl_oparg_t));
			//////
		}
		/////
		break;
	}

	int pid = getpid();
	if (ctl->user_pid != 0 && pid != ctl->user_pid) { //请求的不是同一个进程
		printf("fsdev_begin_request: not same process oldpid=%d, curpid=%d\n", ctl->user_pid, pid );
		///
		ctl->ret = -EFAULT;
		ctl->length = 0;
		ret = write(dev->fd, ctl, sizeof(ioctl_oparg_t));
		free(buf);
		return NULL;
	}

	ctl->user_pid = pid;
	/////
	req->type = ctl->op_type;
	req->ino = ctl->i_ino;
	req->i_usrctx  = (void*)ctl->i_usrctx;
	req->i_usrctx2 = (void*)ctl->i_usrctx2;

	switch (ctl->op_type)
	{
	case OP_LOOKUP:
		req->stat.sub_name = data;
		req->length = ctl->length;
		break;
	case OP_QUERY_STAT:
		req->stat.sub_name = NULL;
		req->length = 0;
		break;
	case OP_SET_STAT:
		req->stat.st = *(struct stat_t*)data;
		break;
	case OP_READDIR:
		req->readdir.d_id = ctl->readdir.d_id;
		req->readdir.d_usrctx  = (void*)ctl->readdir.d_usrctx;
		req->readdir.d_usrctx2 = (void*)ctl->readdir.d_usrctx2;
		req->readdir.is_end = ctl->readdir.is_end;
		req->readdir.fill = (struct dirfill_t*)data; ///
		req->readdir.fill->name_len = 0;
		req->readdir.fill->name[0] = 0;
		break;
	case OP_MKNOD:
		req->mknod.name = data;
		req->mknod.mode = ctl->mknod.mode;
		req->length = ctl->length;
		break;
	case OP_RMNOD:
		req->rmnod.is_rmdir = ctl->rmnod.is_rmdir;
		req->rmnod.name = data;
		req->length = ctl->length;
		break;
	case OP_RENAME:
		req->rename.newdir_ino = ctl->rename.newdir_ino;
		req->rename.old_name = data;
		req->rename.new_name = data + strlen(data) + 1; ////
		break;
	case OP_READ:
	case OP_WRITE:
		req->readwrite.offset = ctl->readwrite.offset;
		req->readwrite.length = ctl->readwrite.length;
		req->readwrite.buffer = data;
		break;

	}

	return req;
}

int fsdev_end_request(void* handle, struct fsdev_request_t* req)
{
	_fsdev_t* dev = (_fsdev_t*)handle;
	if (!dev)return -1;
	int r;
	int w_len = sizeof(ioctl_oparg_t);
	/////
	ioctl_oparg_t* ctl = (ioctl_oparg_t*)((char*)req + sizeof(fsdev_request_t));
	char* data = (char*)((char*)ctl + sizeof(ioctl_oparg_t));

	ctl->i_usrctx = (uint64_t)req->i_usrctx;
	ctl->i_usrctx2 = (uint64_t)req->i_usrctx2;
	ctl->ret = req->ret; if (ctl->ret > 0) ctl->ret = -ctl->ret;
	ctl->length = 0;

	///
	if (ctl->op_type == OP_READDIR && ctl->readdir.is_end) { //not reply
		free(req);
		return 0; 
	}

	////错误
	if (ctl->ret != 0) { // error
		ctl->length = 0;
		r = write(dev->fd, ctl, sizeof(ioctl_oparg_t)); ////
		free(req);
		return r; ////
	}

	/////
	switch (ctl->op_type)
	{
	case OP_LOOKUP:
	case OP_QUERY_STAT:
	case OP_MKNOD:
		{
			struct file_stat_t* st = (struct file_stat_t*)data;

			if(ctl->op_type == OP_MKNOD) *st = *(struct file_stat_t*)&req->mknod.st;
			else *st = *(struct file_stat_t*)&req->stat.st;

			ctl->length = sizeof(struct file_stat_t);
			w_len += ctl->length;
		}
		break;
	case OP_READDIR:
		{
			ctl->readdir.d_usrctx = (uint64_t)req->readdir.d_usrctx;
			ctl->readdir.d_usrctx2 = (uint64_t)req->readdir.d_usrctx2;
			ctl->readdir.is_end = req->readdir.is_end;
			ctl->length = sizeof(struct file_dirfill_t);
			w_len += ctl->length;
		}
		break;
	case OP_RMNOD:
		break;
	case OP_RENAME:
		break;
	case OP_READ:
		ctl->length = req->length;
		w_len += ctl->length;
		break;
	case OP_WRITE:
		ctl->length = req->length;
		break;
	}

	r = write(dev->fd, ctl, w_len);

	if (r <= 0) {
		printf("fsdev_end_request: write ret=%d, err=%d\n", r, errno );
	}

	free(req);
	return r;
}


//////////
#define _MAX_THREAD_CNT  50
struct _fsdev_md_t
{
	name_inode_cache  cache;
	void*             h_mon_dir; ///
	fsdev_mon_dir_t   fs;
	bool              quit;
	pthread_t         thread_ids[_MAX_THREAD_CNT];
	long              thr_cnt;
};

static pthread_t pthread_create(int stack_size, void* (*addr)(void*_p), void* p)
{
	pthread_t tid = 0;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, stack_size);
	int r = pthread_create(&tid, &attr, addr, p);
	pthread_attr_destroy(&attr);
	if (r != 0) return 0;

	return tid;
}
static char* utf8gbk_conv( const char* inn, char* out, int outlen, int is_togbk)
{
	iconv_t cd;
	if(!is_togbk)cd = iconv_open("UTF-8", "GB2312");
	else cd = iconv_open("GB2312", "UTF-8");
	if (cd < 0) {
		printf("iconv_open err=%d\n", errno );
		return NULL;
	}
	char ii[1024]; strcpy(ii, inn); //不知道什么原因。这样才能iconv不异常
	char* pin = (char*)ii;
	char* pout = out;
	memset(out, 0, outlen);
	int inlen = strlen(inn); 
//	printf("utf8gbk_conv: [%s], outlen=%d\n", pin ,outlen );
	if (iconv(cd, &pin, (size_t*)&inlen, &pout, (size_t*)&outlen) < 0) {
		iconv_close(cd);
		return NULL;
	}
	iconv_close(cd);
//	printf("-- is_gogbk=%d, [%s], outlen=%d\n", is_togbk, out, strlen(out) );
	return out;
}

#define IS_GBK()  const char* _f_path = path; char __gbkpath[512]; \
				  if(md->fs.is_gbk_path) { _f_path = utf8gbk_conv( path, __gbkpath, 512, true ); if(!_f_path)_f_path = path; }

static void* fsdev_thread_func(void* _p)
{
	_fsdev_md_t* md = (_fsdev_md_t*)_p;
	name_inode_cache* cache = &md->cache;
	////
	while (!md->quit) {
		///
		fsdev_request_t* req = fsdev_begin_request(md->h_mon_dir);
		if (md->quit) {
			if (req) {
				req->ret = -EINVAL;
				fsdev_end_request(md->h_mon_dir, req);
			}
			///
			break;
		}
		if (!req)continue; 
		////

		req->ret = -EINVAL;
		
		////查询req->ino对应的完整路径名, 这里所有请求的ino，都应该是存在的
		const char* path = (const char*)req->i_usrctx;
		if (path == NULL) { ///
			path = cache->find_path_locked(req->ino);
			if (path == NULL) {
				req->ret = -ENOENT; ///
				fsdev_end_request(md->h_mon_dir, req);
				printf("fsdev_thread_func: not found op_type=%d, ino=%lld path.\n", req->type, req->ino );
				continue; 
			}
			req->i_usrctx = (void*)path;
			cache->unlocked();
		}
		//////////////

		switch (req->type)
		{
		case LOOKUP:
		case QUERY_STAT:
			{
				//////
				char name[512];
				if (req->type == LOOKUP) {
					if(req->ino == XFS_ROOT_ID)sprintf(name, "%s%s", path, req->stat.sub_name);
					else sprintf(name, "%s/%s", path, req->stat.sub_name);
					path = name;
				}

				int r = -EBADF;
				///查询缓存
				r = cache->find_inode_stat(path, &req->stat.st, md->fs.query_timeout ); //单位毫秒
				if (r == 0) {
					req->ret = 0;
					req->length = 0; //printf("*** hit cache [%s]\n", path );
					break; 
				}

				///
				memset(&req->stat.st, 0, sizeof(struct stat_t)); 

				if (req->type == LOOKUP) req->stat.st.flags = 1; //// fs.stat 查询信息时候，flags=1 表示 LOOKUP

				IS_GBK();
				r = -EBADF;
				if(md->fs.stat) r = md->fs.stat( _f_path, &req->stat.st, md->fs.param); ////

				req->ret = r; 
				req->length = 0;
				if (r == 0) { /// success 
					req->stat.st.nlink = 1; ///硬连接
					req->stat.st.mode = req->stat.st.mode;// | S_IRWXO | S_IRWXG | S_IRWXU;
					req->stat.st.ino = req->ino;
					if (req->type == LOOKUP) {
						req->stat.st.ino = cache->find_inode_number( path, true);
					}
					////
					cache->update_inode_stat(req->stat.st.ino, &req->stat.st); ///更新属性到缓存
				}

				/////
	//			printf("QUERY_STAT: optype=%s, [%s], ino=%lld\n", ((req->type==LOOKUP)?"LOOKUP":"QUERY_STAT"), path, req->stat.st.ino);

			}
			break;
		case OP_SET_STAT:
			{
				IS_GBK(); ///
				/////
#define CODEB(F) if(r != 0 ){ req->ret = r;  printf("%s: [%s] err=%d\n",#F, path, r); break; }
#define CD1(F,P) r = -EBADF; if(md->fs.F) r = md->fs.F( _f_path, P, md->fs.param); CODEB(F);
#define CD2(F,P1,P2) r = -EBADF; if(md->fs.F) r = md->fs.F( _f_path, P1, P2, md->fs.param); CODEB(F);
				/////
				cache->invalid_inode_stat(req->ino);
				
				///
				int r = -EINVAL;
				if (req->stat.st.flags & SET_ATTR_MODE) { ////chmod
					
					CD1(chmod, req->stat.st.mode); ///
				}

				if ((req->stat.st.flags & SET_ATTR_UID) || (req->stat.st.flags & SET_ATTR_GID)) {
					int uid = -1; int gid = -1;
					if (req->stat.st.flags&SET_ATTR_UID) uid = req->stat.st.uid;
					if (req->stat.st.flags&SET_ATTR_GID) gid = req->stat.st.gid;
					
					CD2(chown, uid, gid); ////
				}

				if ((req->stat.st.flags & SET_ATTR_ATIME) || (req->stat.st.flags & SET_ATTR_MTIME)) {
					time_t atime = 0; time_t mtime = 0;
					if (req->stat.st.flags&SET_ATTR_ATIME) atime = req->stat.st.atime;
					if (req->stat.st.flags&SET_ATTR_MTIME) mtime = req->stat.st.mtime;
					
					CD2(utime, atime, mtime); ///
				}

				if (req->stat.st.flags&SET_ATTR_SIZE) {
					
					CD1(truncate, req->stat.st.size); /////
				}

				req->ret = 0; // success
			}
			break;
		case OP_READDIR:
			{
				IS_GBK(); ///
				////
				int r = -EBADF;
				struct read_dir_t dir;
				dir.d_id = req->readdir.d_id;
				dir.d_usrctx = req->readdir.d_usrctx;
				dir.d_usrctx2 = req->readdir.d_usrctx2;
				dir.is_end = req->readdir.is_end;
				dir.name = req->readdir.fill->name;
				dir.is_stat = false;
				memset(&dir.stat, 0, sizeof(stat_t));

				if (md->fs.readdir) {
					while (true) {
						dir.name[0] = 0; //读前，设置为空
						dir.is_stat = false;
						memset(&dir.stat, 0, sizeof(stat_t));
						r = md->fs.readdir( _f_path, &dir, md->fs.param);
						if ( strcmp(dir.name, ".") == 0 || strcmp(dir.name, "..") == 0 ) continue;
						break;
					}
				}

				req->readdir.d_usrctx = dir.d_usrctx;
				req->readdir.d_usrctx2 = dir.d_usrctx2;
				req->readdir.fill->ino = 0;
				req->readdir.fill->type = 0; // DT_UNKNOWN
				req->readdir.fill->name_len = strlen(dir.name); 
				///
				if (req->readdir.fill->name_len > 0 && r == 0 ) { // success
					char name[512]; char sub_name[260];
					if (md->fs.is_gbk_path) { 
						if (utf8gbk_conv(dir.name, sub_name, sizeof(sub_name), false)) {
							strcpy(dir.name, sub_name);
							req->readdir.fill->name_len = strlen(dir.name);
						}
						////
					}
					
					if (req->ino == XFS_ROOT_ID)sprintf(name, "%s%s", path, dir.name );
					else sprintf(name, "%s/%s", path, dir.name );
					req->readdir.fill->ino = cache->find_inode_number(name, true); /// new inode number 
				//	printf("READDIR:[%s]\n", name );
					///
					if (req->readdir.fill->ino == 0) {
						r = -EINVAL;
					}
					else {
						if ( dir.is_stat && !dir.is_end ) { //同时读取到了文件信息
							////
							 dir.stat.ino = req->readdir.fill->ino;
							 dir.stat.nlink = 1; 

							cache->update_inode_stat(dir.stat.ino, &dir.stat); ///更新到缓存
						}
						///////
					}
					/////////
				}

				req->ret = r;
				req->length = 0;
			}
			break;

		case OP_MKNOD:
			{
				/////
				char name[512];
				int mode = req->mknod.mode;
				if (req->ino == XFS_ROOT_ID)sprintf(name, "%s%s", path, req->mknod.name);
				else sprintf(name, "%s/%s", path, req->mknod.name);
				path = name;
				//////
				memset(&req->mknod.st, 0, sizeof(stat_t)); 

				cache->invalid_inode_stat(req->ino); ///

				IS_GBK(); ///
				int r = -EBADF;
				if (S_ISDIR(mode)) { // mkdir
					if (md->fs.mkdir) r = md->fs.mkdir( _f_path, mode, md->fs.param);
				}
				else if (S_ISREG(mode)) {
					if (md->fs.mknod) r = md->fs.mknod( _f_path, mode, md->fs.param);
				}
				else {
					r = -EACCES;
					printf("mknod: not unknow mode=0x%X create[%s]\n", mode, path );
				}
				///////
				
				if (r == 0) { //查询属性
					r = -EBADF;
					if (md->fs.stat) r = md->fs.stat( _f_path, &req->mknod.st, md->fs.param);
					////
					if (r == 0) {
						req->mknod.st.nlink = 1;
						req->mknod.st.ino = cache->find_inode_number(path, true); //生成新的ino

						/////
						cache->update_inode_stat(req->mknod.st.ino, &req->mknod.st); ///
					}
					//////
				}
				
				req->ret = r;
				req->length = 0;
				////////
			}
			break;

		case OP_RMNOD:
			{
				/////
				char name[512]; 
				int is_rmdir = req->rmnod.is_rmdir;
				if (req->ino == XFS_ROOT_ID)sprintf(name, "%s%s", path, req->rmnod.name);
				else sprintf(name, "%s/%s", path, req->rmnod.name);
				path = name;
				//////
				IS_GBK(); ///
				int r = -EBADF;
				if (is_rmdir) {
					if (md->fs.rmdir) r = md->fs.rmdir( _f_path, md->fs.param);
				}
				else {
					if (md->fs.unlink) r = md->fs.unlink( _f_path, md->fs.param);
				}
				/////
				req->ret = r;
				req->length = 0; 
			}
			break;

		case OP_RENAME:
			{
				////
				char old_path[512]; char new_path[512];
				uint64_t newdir_ino = req->rename.newdir_ino;
				if (req->ino == XFS_ROOT_ID) sprintf(old_path, "%s%s", path, req->rename.old_name);
				else sprintf(old_path, "%s/%s", path, req->rename.old_name);
				if (req->ino == newdir_ino) { //同一个目录下
					if (req->ino == XFS_ROOT_ID) sprintf(new_path, "%s%s", path, req->rename.new_name);
					else sprintf(new_path, "%s/%s", path, req->rename.new_name);
				}
				else {
					const char* np = cache->find_path_locked(newdir_ino);
					if (np == NULL) {
						req->ret = -ENOENT;
						req->length = 0;
						printf("rename: newdir_ino=%lld, not found path.\n", newdir_ino );
						break;
					}
					if (newdir_ino == XFS_ROOT_ID) sprintf(new_path, "%s%s", np, req->rename.new_name);
					else sprintf(new_path, "%s/%s", np, req->rename.new_name);
					////
					cache->unlocked();
				}
				//////
				if (md->fs.is_gbk_path) {
					char o[512], n[512];
					if (utf8gbk_conv(old_path, o, sizeof(o), 1)) strcpy(old_path, o);
					if (utf8gbk_conv(new_path, n, sizeof(n), 1)) strcpy(new_path, n);
				}
				int r = -EBADF;
				if (md->fs.rename) r = md->fs.rename(old_path, new_path, md->fs.param);
				////
				req->ret = r;
				req->length = 0; 
			}
			break;

		case OP_READ:
		case OP_WRITE:
			{
				IS_GBK(); ///
				////
				int r = -EBADF;
				if (req->type == OP_READ) {
					if (md->fs.read) r = md->fs.read( _f_path, req->readwrite.buffer, req->readwrite.offset, req->readwrite.length, md->fs.param);
				}
				else {
					if (md->fs.write) r = md->fs.write( _f_path, req->readwrite.buffer, req->readwrite.offset, req->readwrite.length, md->fs.param);
					/////
					cache->invalid_inode_stat(req->ino); ///
				}
				////
				if (r >= 0 ) { // success
					req->ret = 0; 
					req->length = r;
				}
				else {
					req->ret = r;
					req->length = 0; 
					/////
				}
				///////
			}
			break;
		}
		////

		fsdev_end_request(md->h_mon_dir, req); ///  end request ...

	}

	atomic_dec(&md->thr_cnt); ///
	//////
	return NULL;
}

void* fsdev_mon_dir_create(struct fsdev_mon_dir_t* fs)
{
	_fsdev_md_t* md = NULL;
	if (!fs || !fs->mon_dir)return NULL;

	struct xfs_mount_t mnt;
	mnt.root_ino = XFS_ROOT_ID;
	mnt.query_tmo = fs->query_timeout;
	mnt.trans_tmo = fs->trans_timeout;
	mnt.entry_tmo = fs->entry_timeout;
	mnt.attr_tmo = fs->attr_timeout;
	mnt.root_gid = fs->root_gid;
	mnt.root_uid = fs->root_uid;
	mnt.is_direct_io = fs->is_direct_io; ///直接读写

	void* hdir = fsdev_mount(fs->mon_dir, &mnt);
	if (!hdir) {
		printf("fsdev_mount err\n");
		return NULL;
	}
	md = new _fsdev_md_t;
	md->fs = *fs;
	md->h_mon_dir = hdir;
	md->quit = false;
	md->thr_cnt = 0;
	
	for (int i = 0; i < md->fs.thread_cnt; ++i) {
		pthread_t tid = pthread_create(1024 * 1024 * 2, fsdev_thread_func, md); ///
		if (tid) {
			++md->thr_cnt;
		}
	}

	////
	return md;
}

int fsdev_mon_dir_close(void* handle)
{
	_fsdev_md_t* md = (_fsdev_md_t*)handle;
	if (!md)return -1;
	///
	md->quit = true;

	while (md->thr_cnt > 0) {
		fsdev_wakeup(md->h_mon_dir);
		msleep(300);
		printf("wait thread exit thr_cnt=%d\n", md->thr_cnt );
	}
	
	fsdev_umount(md->h_mon_dir); /// umount ...

	delete md;
	/////
	return 0;
}


/////////////
#if 0

bool __quit = false;
#include <signal.h>
#include <utime.h>
void sighandler(int num)
{
	printf("SIGUSER num=%d\n", num );
//	umount("/home/xfsredir/mon_dir");
	__quit = true;
}
static char* get_path(const char* path, char* buf)
{
	const char* root = "/root"; //设置重定向的目录
	/////
	if (strcmp(path, "/") == 0) strcpy(buf, root);
	else sprintf(buf, "%s/%s", root, path);
	return buf;
}

int i_stat(const char* path, struct stat_t* st, void* param )
{
	char namebuf[512];
	struct stat64 ss; 
	if (stat64( get_path(path, namebuf), &ss) < 0) {
		return -errno;
	}
	st->size = ss.st_size;
	st->mode = ss.st_mode; st->atime = ss.st_atime; st->ctime = ss.st_ctime; st->mtime = ss.st_mtime;
	st->uid = ss.st_uid; st->gid = ss.st_gid;
	return 0;
}

int i_readdir(const char* path, struct read_dir_t* item, void* param)
{
	if (!item->d_usrctx) { //
		char namebuf[512];
		DIR* d = opendir( get_path(path, namebuf) );
		if (!d) {
			return errno;
		}
		item->d_usrctx = d;
	}
	DIR* d = (DIR*)item->d_usrctx;
	///
	if (item->is_end) { /// end
		closedir(d);
		printf("*** read_dir closed.\n");
		return 0;
	}
	/////
	
	struct dirent* ent = readdir(d);
	if (!ent) {
		int err = errno;
		printf("call readdir end err=%d\n", err );
		return err;
	}else{
	//	printf("readdir: [%s]\n", ent->d_name );
		strcpy(item->name, ent->d_name); ////
	}

	return 0;
}
int i_chmod(const char* path, int mode, void* param)
{
	printf("--chmod: [%s] mode=0x%X\n", path, mode);
	char namebuf[512];
	if (chmod(get_path(path, namebuf), mode) < 0) {
		return -errno;
	}
	return 0;
}
int i_chown(const char* path, int uid, int gid, void* param)
{
	printf("--chown: [%s] uid=%d,gid=%d\n", path, uid,gid);
	char namebuf[512];
	if (chown(get_path(path, namebuf), uid, gid) < 0) return -errno;
	return 0;
}
int i_utime(const char* path, time_t atime, time_t mtime, void* param)
{
	printf("--utime: [%s] atime=%ld, mtime=%ld\n", path, atime,mtime );
	char namebuf[512];
	struct utimbuf ut;
	ut.actime = atime; ut.modtime = mtime;
	if (utime(get_path(path, namebuf), &ut) < 0) return -errno;
	return 0;
}
int i_truncate(const char* path, int64_t newsize, void* param)
{
	char namebuf[512];
	printf("--truncate: [%s] newsize=%lld\n", path, newsize);
	if (truncate(get_path(path, namebuf), newsize) < 0) return -errno;
	return 0;
}
int i_mknod(const char* path, int mode, void* param)
{
	printf("mknod: [%s] mode=0x%X\n", path ,mode );
	char namebuf[512];
	int r = mknod(get_path(path, namebuf), S_IFREG, 0);
	if (r < 0) {
		return -errno;
	}
	return 0;
}
int i_mkdir(const char* path, int mode, void* param)
{
	char namebuf[512];
	if (mkdir(get_path(path, namebuf), mode ) < 0) {
		return -errno;
	}
	return 0;
}
int i_rmdir(const char* path, void* param)
{
	char namebuf[512];
	if (rmdir(get_path(path, namebuf)) < 0) {
		return -errno;
	}
	return 0;
}
int i_unlink(const char* path, void* param)
{
	char namebuf[512];
	if (remove(get_path(path, namebuf)) < 0) {
		return -errno;
	}
	return 0;
}

int i_rename(const char* old_path, const char* new_path, void* param)
{
	char oldname[512]; char newname[512];
	get_path(old_path, oldname); get_path(new_path, newname);
	if (rename(oldname, newname) < 0) {
		return -errno;
	}
	return 0;
}

int i_read(const char* path, char* buffer, int64_t offset, int length, void* param)
{
	printf("i_read: offset=%lld, length=%d, [%s]\n", offset, length, path );
	char namebuf[512];
	///
	int fd = open( get_path(path, namebuf), O_RDONLY); 
	if (fd < 0) {
		return -errno;
	}
	int r = lseek64(fd, offset, SEEK_SET);
	if (r < 0) {
		int err = errno;
		close(fd);
		return err;
	}
	r = read(fd, buffer, length);
	if (r < 0) {
		int err = errno;
		close(fd);
		return err;
	}
	////
	close(fd);

	return r ;
}
int i_write(const char* path, char* buffer, int64_t offset, int length, void* param)
{
	printf("i_write: offset=%lld, length=%d, [%s]\n", offset, length, path);
	char namebuf[512];
	///
	int fd = open(get_path(path, namebuf), O_WRONLY);
	if (fd < 0) {
		return -errno;
	}
	int r = lseek64(fd, offset, SEEK_SET);
	if (r < 0) {
		int err = errno;
		printf("lseek64 err=%d\n", err );
		close(fd);
		return err;
	}
	r = write(fd, buffer, length);
	if (r < 0) {
		int err = errno;
		close(fd);
		return err;
	}
	////
	close(fd);

	return r;
}

int main(int argc, char** argv)
{
	//
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGKILL, sighandler);
	////
	
	fsdev_mon_dir_t fs;
	fs.mon_dir = "/home/xfsredir/mon_dir";
	fs.thread_cnt = 3;
	fs.root_gid = fs.root_uid = 1;
	
	fs.query_timeout = 10*1000;
	fs.trans_timeout = 30*1000;
	fs.entry_timeout = 900;
	fs.attr_timeout = 900;
	fs.is_direct_io = 1; ///
	fs.is_gbk_path = 0;

	fs.param = NULL;

	fs.stat = i_stat;
	fs.readdir = i_readdir; 
	fs.chmod = i_chmod;
	fs.chown = i_chown;
	fs.utime = i_utime;
	fs.truncate = i_truncate;
	fs.mknod = i_mknod;
	fs.mkdir = i_mkdir;
	fs.rmdir = i_rmdir;
	fs.unlink = i_unlink;
	fs.rename = i_rename; ///
	fs.read = i_read; ///
	fs.write = i_write; ///

	if (argc == 2) fs.mon_dir = argv[1]; ///

	void* md = fsdev_mon_dir_create(&fs);
	if (!md)exit(0);

	while (!__quit)sleep(1);

	fsdev_mon_dir_close(md);

	return 0;
}

#endif

