///////by fanxiushu 2016-08-29
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "fsdev.h"
#include "ftpclient.h"
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <string>
#include <list>
#include <getopt.h>
using namespace std;

struct fscbk_param_t
{
	string  svrip;
	int     port;
	string  user;
	string  pwd;
	string  root_dir;
	///
	int     retry_count; //
	int     query_timeout;
	int     trans_timeout;

	string  mon_dir; ///

	pthread_mutex_t  lck;
	list<int> ftp_pool;   ///简单的连接池,包含所有的FTP CTL连接
};

struct hftp_t
{
	int   ftp;
	void* hFind;
	fscbk_param_t* p;
	char rpath[300];
};

static int ftp_init(fscbk_param_t* p, hftp_t* f, const char* path )
{
	f->ftp = -1;
	f->hFind = NULL;
	f->p = p;
	///
	int fd = -1;
	pthread_mutex_lock(&p->lck);
	if (p->ftp_pool.size() > 0) {
		fd = p->ftp_pool.front(); 
		p->ftp_pool.pop_front(); 
	}
	pthread_mutex_unlock(&p->lck);
	////
	if (fd < 0) {
		fd = ftp_login(p->svrip.c_str(), p->port, p->user.c_str(), p->pwd.c_str(), p->query_timeout);
		if (fd < 0) {
			printf("FTP: Login [%s] err\n", p->svrip.c_str());
			return -1;
		}
	}
	f->ftp = fd;

	if (p->root_dir == "/") strcpy(f->rpath, path);
	else sprintf(f->rpath, "%s/%s", p->root_dir.c_str(), path); 
	///
	return 0;
}
static void ftp_deinit(hftp_t* f, bool is_free )
{
	if (f->hFind)ftp_find_close(f->hFind);
	f->hFind = 0;
	if (is_free) {
		ftp_bye(f->ftp);
	}
	else {
		pthread_mutex_lock(&f->p->lck);
		f->p->ftp_pool.push_back(f->ftp); ////
		pthread_mutex_unlock(&f->p->lck);
	}
	////
	f->ftp = -1;
}
#define IS_FREE(r)  (((r)==-1)?true:false)

#if 1

bool __quit = false;
#include <signal.h>
#include <utime.h>
void sighandler(int num)
{
	printf("SIGUSER num=%d\n", num);
	//	umount("/home/xfsredir/mon_dir");
	__quit = true;
}

////
#define CBK_BEGIN() \
     fscbk_param_t* p = (fscbk_param_t*)param; \
     int ret = -EACCES; \
     for (int i = 0; i < p->retry_count; ++i) { \
         hftp_t f; \
         if ( ftp_init(p, &f, path) < 0 ) { sleep(1); continue; } 

#define CBK_END() \
         ftp_deinit(&f, IS_FREE(r) ); \
         if (r < 0) { \
             if(r== -1 )continue; \
             break; \
		 } \
         ret = r; \
         break;   \
    }

static void fill_i_stat_with_ftpinfo(struct stat_t* st, ftp_fileinfo_t* info)
{
	///
	st->uid = st->gid = 0; /// root
	st->mode = S_IRWXO | S_IRWXG | S_IRWXU; //所有文件读写执行
	st->nlink = 1;

	st->size = info->file_size;
	if (info->is_dir) st->mode |= S_IFDIR; else st->mode |= S_IFREG;
	st->blocks = (st->size + 4096 - 1) / 4096; /// 4K page
	st->atime = st->ctime = st->mtime = info->mtime;
}

int i_stat(const char* path, struct stat_t* st, void* param)
{

	ftp_fileinfo_t info;
	CBK_BEGIN();
	int r = ftp_stat(f.ftp, f.rpath, &info, p->query_timeout);
	CBK_END();

	if (ret == 0) {
		///
		fill_i_stat_with_ftpinfo(st, &info);
		
		//////
	}
	else{
		if (st->flags == 1) { // LOOKUP
			//这里错误码太少了，应该判断究竟是哪种错误!
			ret = -ENOENT; ///
		}
	}
	////
	return ret;
}
int i_readdir(const char* path, struct read_dir_t* item, void* param)
{
	fscbk_param_t* p = (fscbk_param_t*)param;
	////
	if (!item->d_usrctx) { //第一次查询
		printf("readdir [%s] begin\n", path );

		hftp_t* f = new hftp_t; bool ok = false;
		for (int i = 0; i < p->retry_count; ++i) {
			if (ftp_init(p, f, path) < 0) { sleep(1); continue; }
			int r = ftp_find_open(f->ftp, &f->hFind, f->rpath, "", p->query_timeout);
			if (r < 0) {
				ftp_deinit(f, IS_FREE(r));
				if (r == -1)continue;
				return -ENOENT; /// not exists 
			}
			ok = true; break;
		}
		if (!ok) { delete f; return -EACCES; }
		////
		
		item->d_usrctx = f;
	}
	hftp_t* f = (hftp_t*)item->d_usrctx;
	////
	if (item->is_end) {//查询结束
		ftp_deinit(f, IS_FREE(0));
		delete f;
		printf("readdir [ %s ] closed\n", path );
		return 0;
	}
	//////
	ftp_fileinfo_t info;
	int r = ftp_find_next(f->hFind, &info);
	if (r > 0) {//查询到子目录
		///
		strcpy(item->name, info.name);
		/////同时填充info信息
		item->is_stat = true; ///

		fill_i_stat_with_ftpinfo(&item->stat, &info); ////
		////
	}

	return 0;
}
int i_chmod(const char* path, int mode, void* param)
{
	return 0;
}
int i_chown(const char* path, int uid, int gid, void* param)
{
	return 0;
}
int i_utime(const char* path, time_t atime, time_t mtime, void* param)
{
	return 0;
}

int i_truncate(const char* path, int64_t newsize, void* param)
{
	////
	CBK_BEGIN();
	int r = ftp_set_newsize(f.ftp, f.rpath, newsize, p->query_timeout);
	CBK_END();
	///
	return ret;
}
int i_mknod(const char* path, int mode, void* param)
{
	return i_truncate(path, 0, param);
}
int i_mkdir(const char* path, int mode, void* param)
{
    ////
	CBK_BEGIN();
	int r = ftp_create_directory(f.ftp, f.rpath);
	CBK_END();

	return ret;
}
int i_rmdir(const char* path, void* param)
{
    ////
	CBK_BEGIN();
	int r = ftp_delete_directory(f.ftp, f.rpath);
	CBK_END();

	return ret;
}
int i_unlink(const char* path, void* param)
{
    ///
	CBK_BEGIN();
	int r = ftp_delete_file(f.ftp, f.rpath);
	CBK_END();

	return ret;
}
int i_rename(const char* old_path, const char* new_path, void* param)
{
	const char* path = old_path; ///
	CBK_BEGIN();
	char n_path[512]; 
	if (p->root_dir == "/") strcpy(n_path, new_path);
	else sprintf(n_path, "%s/%s", p->root_dir.c_str(), new_path);
	int r = ftp_rename(f.ftp, f.rpath, n_path); ///
	CBK_END();

	return ret;
}
int i_read(const char* path, char* buffer, int64_t offset, int length, void* param)
{
	CBK_BEGIN();
	int r = ftp_read_offset(f.ftp, f.rpath, buffer, offset, length, p->trans_timeout, NULL, NULL);
	CBK_END();

	return ret;
}
int i_write(const char* path, char* buffer, int64_t offset, int length, void* param)
{
	CBK_BEGIN();
	int r = ftp_write_offset(f.ftp, f.rpath, buffer, offset, length, p->trans_timeout, NULL, NULL);
	CBK_END();

	return ret;
}

struct option opts[] = {
	{"host", required_argument , NULL, 'h'},
	{"user", required_argument , NULL, 'u'},
	{"pwd",  required_argument , NULL, 'p'},
	{"mondir",  required_argument , NULL, 'd'},
	{"gbk",  no_argument,        NULL, 'k'},
	{"directio",  no_argument,   NULL, 'o'},
};

int main(int argc, char** argv)
{
	//
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGKILL, sighandler);
	signal(SIGPIPE, SIG_IGN); 
	////
	fscbk_param_t cbk_p;
	int is_gbk_path = 0; /////路径是否转换成 GB2312，用于访问windows系统
	int is_dio = 0; //是否直接读写，不走linux内核缓存
	pthread_mutex_init(&cbk_p.lck, NULL); ///
	///
	cbk_p.port = 21;
	cbk_p.svrip = "";// "192.168.88.1";//"192.168.174.129";
	cbk_p.user = "";// "anonymous";
	cbk_p.pwd =  "";
	cbk_p.root_dir = "/";
	cbk_p.retry_count = 10;
	cbk_p.mon_dir = "";// "/home/xfsredir/mon_dir";
	cbk_p.query_timeout = 15;
	cbk_p.trans_timeout = 40;
	/////
	const char* errmsg = "--usage: ./fsdev -h 192.168.88.1:21 -u anonymous -p pwd -d /home/mondir -k -o\n"
		"-h --host serverip[:port]\n"
		"-u --user user name\n"
		"-p --pwd password\n"
		"-d --mondir monitor directory\n"
		"-k --gbk  use gbk path\n"
		"-o --directio direct IO\n";
	int opt;
	while ((opt = getopt_long(argc, argv, "h:u:p:d:ko", opts, NULL)) != -1) {
		switch (opt) {
		case 'h': {
			const char* h = optarg; const char* ptr = strchr(h, ':');
			if (ptr) { cbk_p.svrip = string(h, ptr - h); cbk_p.port = atoi(ptr + 1); }
			else { cbk_p.svrip = h; cbk_p.port = 21; }
		}break;
		case 'u':cbk_p.user = optarg; break;
		case 'p':cbk_p.pwd = optarg; break;
		case 'd':cbk_p.mon_dir = optarg; break;
		case 'k':is_gbk_path = 1; break;
		case 'o':is_dio = 1; break;
		default: printf("%s\n", errmsg); exit(-1);
		}
	}
	if (cbk_p.mon_dir.empty() || cbk_p.svrip.empty()) {
		printf("%s\n", errmsg); exit(-1);
	}

	fsdev_mon_dir_t fs;

	fs.mon_dir = cbk_p.mon_dir.c_str();
	fs.thread_cnt = 10;
	fs.root_gid = fs.root_uid = 0;

	fs.query_timeout = cbk_p.query_timeout * 1000;
	fs.trans_timeout = cbk_p.trans_timeout * 1000;
	fs.entry_timeout = 3*1000;
	fs.attr_timeout =  1*100;
	fs.is_direct_io = is_dio; ///
	fs.is_gbk_path = is_gbk_path; 
	fs.param = &cbk_p;

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
	fs.write = i_write; 
	
	////
	void* md = fsdev_mon_dir_create(&fs);
	if (!md)exit(0);
	/////
	while (!__quit)sleep(1);

	fsdev_mon_dir_close(md);
	////
	return 0;
}
#endif

