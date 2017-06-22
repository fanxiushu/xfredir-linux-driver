/////by Fanxiushu 2014-12-19

#pragma once

#ifdef WIN32
typedef __int64  int64_t; 
#else
#define MAX_PATH                            260
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#endif

struct ftp_fileinfo_t
{
	char     name[MAX_PATH];
	int      is_dir;
	int      attr;
	int64_t  file_size;
	time_t   mtime;
};

int ftp_login(const char* str_ip, int port, const char* user, const char* passwd, int tmo);
int ftp_bye(int fd);

int ftp_set_current_directory(int fd, const char* remote_curr_dir);
int ftp_create_directory(int fd, const char* remote_dir);
int ftp_rename(int fd, const char* old_name, const char* nw_name);
int ftp_delete_directory(int fd, const char* remote_dir);
int ftp_delete_file(int fd, const char* remote_path);
int ftp_ping(int fd, int tmo, int* out_ms_time);
int ftp_stat(int fd, const char* path_name, ftp_fileinfo_t* info, int timeout);
int64_t ftp_get_filesize(int fd, const char* rpath);
int ftp_set_newsize(int fd, const char* rpath, int64_t newsize, int timeout);

/////find directory
int   ftp_find_open(int fd, void** phFind, const char* path, const char* option_name, int tmo);
int   ftp_find_next(void* hfind, ftp_fileinfo_t* info);
int   ftp_find_close(void* hfind);

///read /write
int ftp_read_offset(int fd, const char* path_name, char* buf, int64_t offset, int len, int tmo,
	int(*progress)(int curr_trans, int total_len, void* pram), void* param );
int ftp_write_offset(int fd, const char* path_name, char* buf, int64_t offset, int len, int tmo,
	int(*progress)(int curr_trans, int total_len, void* pram), void* param);

