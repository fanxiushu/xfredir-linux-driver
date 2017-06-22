/////By Fanxiushu 2014-12-19
/*******
FTP客户端最初开发于2007年左右，
在 2014年重新修改，用以完成本项目的需求，
范秀树 2014

********/
/////

#define BUF_SIZE   8192

#ifdef WIN32
#include <WinSock2.h>
#pragma comment(lib,"ws2_32")
typedef  __int64                  int64_t;
typedef  unsigned __int64         uint64_t;
typedef  int                      int32_t;
typedef  unsigned int             uint32_t;
#define atoll _atoi64
#define strcasecmp  stricmp
#define strncasecmp strnicmp

#else
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#define closesocket(s) close(s)
typedef unsigned int  DWORD;
#include <errno.h>
#include <poll.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdarg.h>
#include <time.h>

static unsigned long GetTickCount()
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);

}

#endif

extern "C" { 
#include "ftpparse.h"
}
#include <stdio.h>
#include "ftpclient.h"
#include <time.h>
#include <string>
#include <list>
using namespace std;

////
static int simple_connect(const char* str_ip, int port, int tmo)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	sockaddr_in addr; memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	uint32_t ip = inet_addr(str_ip);
	if (ip == INADDR_NONE){
#ifndef WIN32
		res_init(); //确保改变 /etc/resolv.conf能马上生效
#endif
		hostent* p = gethostbyname(str_ip);
		if (!p){
			closesocket(sock);
			return -1;
		}
		memcpy(&ip, (p->h_addr_list[0]), sizeof(uint32_t));
	}
	memcpy(&addr.sin_addr, &ip, sizeof(uint32_t));
#ifdef WIN32
	fd_set wrst; FD_ZERO(&wrst); FD_SET(sock, &wrst);
	fd_set exst; FD_ZERO(&exst); FD_SET(sock, &exst);
	unsigned long arg = 1;
	ioctlsocket(sock, FIONBIO, &arg);

	int r = connect(sock, (sockaddr*)&addr, sizeof(addr));
	if (r< 0){
		if (WSAGetLastError() != WSAEWOULDBLOCK){
			closesocket(sock);
			return -1;
		}
		struct timeval timeout; timeout.tv_sec = tmo; timeout.tv_usec = 0;
		int status = select(sock + 1, NULL, &wrst, &exst, &timeout);
		if (status <= 0){
			closesocket(sock);
			return -1;
		}
		if (FD_ISSET(sock, &exst)){
			closesocket(sock);
			return -1;
		}

	}
	///
#else

	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
	unsigned long arg = 1;
	ioctl(sock, FIONBIO, &arg);

	int r = connect(sock, (sockaddr*)&addr, sizeof(addr));
	if (r < 0){
		if (errno != EINPROGRESS){
			closesocket(sock);
			return -1;
		}
		///
		pollfd ufds; ufds.fd = sock;
		ufds.events = POLLIN | POLLOUT; ufds.revents = 0;
		int status = poll(&ufds, 1, tmo * 1000);
		if (status <= 0){
			closesocket(sock);
			return -1;
		}
		if (ufds.revents & POLLERR || ufds.revents&POLLHUP){
			closesocket(sock);
			return -1;
		}
	}

#endif
	///
	int tcp_nodelay = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&tcp_nodelay, sizeof(int));
	//////

	return sock;
}

int block_read(int fd, char* buf, int len, int tmo /*= 15*/)
{
	int curr_len = 0;

#ifdef WIN32
	fd_set rdst; FD_ZERO(&rdst); FD_SET(fd, &rdst);
	struct timeval timeout; timeout.tv_sec = tmo; timeout.tv_usec = 0;
	int status = select(fd + 1, &rdst, NULL, NULL, tmo != 0 ? &timeout : NULL);
#else
	struct pollfd ufds;
	ufds.fd = fd; ufds.events = POLLIN; ufds.revents = 0;
	int ms = tmo != 0 ? tmo * 1000 : -1;
	int status = poll(&ufds, 1, ms);
#endif
	///

	if (status < 0)
		return -1;
	else if (status == 0)
		return 0;
	///
	curr_len = recv(fd, buf, len, 0);
	if (curr_len <= 0)
		return -1;
	return curr_len;
}

int read_complete(int fd, char* buf, int len, int tmo)
{
	int sz = 0;
	while (sz < len){
#ifdef WIN32
		fd_set rdst; FD_ZERO(&rdst); FD_SET(fd, &rdst);
		struct timeval timeout; timeout.tv_sec = tmo; timeout.tv_usec = 0;
		int status = select(fd + 1, &rdst, NULL, NULL, tmo != 0 ? &timeout : NULL);
#else
		struct pollfd ufds;
		ufds.fd = fd; ufds.events = POLLIN; ufds.revents = 0;
		int ms = tmo != 0 ? tmo * 1000 : -1;
		int status = poll(&ufds, 1, ms);
#endif
		///
		if (status <= 0)
			return -1;
		int r = recv(fd, buf + sz, len - sz, 0);
		if (r <= 0)
			return -1;
		sz += r;
	}
	return sz;
}


//can recv multiline 

int get_response(int fd, char* buf, int len, int tmo)
{
	int sz = 0;
	char* newline = buf;
	char code[4]; code[3] = '\0';
	while (sz < len - 1){

#ifdef WIN32
		fd_set rdst; FD_ZERO(&rdst); FD_SET(fd, &rdst);
		struct timeval timeout; timeout.tv_sec = tmo; timeout.tv_usec = 0;
		int status = select(fd + 1, &rdst, NULL, NULL, tmo != 0 ? &timeout : NULL);
#else
		struct pollfd ufds;
		ufds.fd = fd; ufds.events = POLLIN; ufds.revents = 0;
		int ms = tmo != 0 ? tmo * 1000 : -1;
		int status = poll(&ufds, 1, ms);
#endif
		///
		if (status <= 0)
			return -1;

		int r = recv(fd, buf + sz, len - 1 - sz, 0);
		if (r <= 0)
			return -1;
		sz += r;
		buf[sz] = '\0'; //printf("{%s}\n", buf);
		char* str = NULL;
		while ((str = strstr(newline, "\r\n")) != NULL){
			if (newline == buf){
				if (newline[3] != '-'){
					*str = '\0';
					return sz;
				}
				else{
					strncpy(code, newline, 3);
				}
			}
			else{
				if (newline[3] == ' ' && strncmp(newline, code, 3) == 0){//last line
					*str = '\0';
					return sz;
				}
			}
			////
			newline = str + 2;
		}
	}
	///
	printf("maby not recv all socket data.\n");
	////
	return sz;
}
///读一行的数据,offset是在缓存buf中的偏移
static int read_line(int fd, char* buf, int offset, int buf_len, int timeout)
{
	buf[offset] = 0;
	char* str = strstr(buf, "\r\n");
	if (str){
		*str = 0;
		return offset;
	}
	//////
	int sz = offset;
	while (sz < buf_len){
		fd_set wrst; FD_ZERO(&wrst); FD_SET(fd, &wrst);
		struct timeval tmo; memset(&tmo, 0, sizeof(tmo)); tmo.tv_sec = timeout;
		int status = select(fd + 1, &wrst, NULL, NULL, timeout != 0 ? &tmo : NULL);
		if (status <= 0)
			return -1;
		//	else if( status == 0)
		//		return 0;
		int r = recv(fd, buf + sz, buf_len - 1 - sz, 0);
		if (r <= 0)
			return -1;
		sz += r;
		buf[sz] = '\0';
		char* str = strstr(buf, "\r\n");
		if (str){
			*str = '\0';
			return sz;
		}
	}
	return sz;
}

int write_complete(int fd, char* buf, int len, int tmo /*= 30*/)
{
	int sz = 0;
	while (sz < len){

#ifdef WIN32
		struct timeval timeout; timeout.tv_sec = tmo; timeout.tv_usec = 0;
		fd_set wrst; FD_ZERO(&wrst);
		FD_SET(fd, &wrst);
		int status = select(fd + 1, NULL, &wrst, NULL, tmo != 0 ? &timeout : NULL);
#else
		struct pollfd ufds;
		ufds.fd = fd; ufds.events = POLLOUT; ufds.revents = 0;
		int ms = tmo != 0 ? tmo * 1000 : -1;
		int status = poll(&ufds, 1, ms);
#endif
		//
		if (status <= 0)
			return -1;
		int r = send(fd, buf + sz, len - sz, 0);
		if (r <= 0)
			return -1;
		sz += r;
	}
	return sz;
}

int ftp_login(const char* str_ip, int port, const char* user, const char* passwd, int tmo )
{
	int fd = -1; int r;
	fd = simple_connect(str_ip, port, tmo); 
	if (fd < 0){
		printf("connect FTP Server [%s:%d] Error.\n", str_ip, port );
		return -1;
	}

	char buf[BUF_SIZE];
	r = get_response(fd, buf, BUF_SIZE, tmo);
	if (r <= 0)
	{
		goto error;
	}
	//
	sprintf(buf, "USER %s\r\n", user);
	r = write_complete(fd, buf, strlen(buf), tmo);
	if (r <= 0){
		goto error;
	}
	r = get_response(fd, buf, BUF_SIZE, tmo);
	if (r <= 0)
		goto error;
	if (strncmp(buf, "230", 3) == 0)
		return fd;
	sprintf(buf, "PASS %s\r\n", passwd);
	r = write_complete(fd, buf, strlen(buf), tmo);
	if (r <= 0)
		goto error;
	r = get_response(fd, buf, BUF_SIZE, tmo);
	if (r <= 0)goto error;
	if (buf[0] != '2')
		goto error;
	///
	ftp_set_current_directory(fd, "/"); ///
	//Sleep(1000);
	//	printf("Login Success !!!");
	return fd;
error:
	closesocket(fd);
	return -1;
}

////
#define FTP_CMD0(c)   { int _ss__ret = write_complete(fd,buf,strlen(buf),12);if( _ss__ret<= 0){return -1;} \
					   _ss__ret = get_response(fd,buf,BUF_SIZE ,12);if(_ss__ret<=0){return -1;}    \
					   if( buf[0] != c ) {printf("ftp cmd error: [%s]\n",buf);return -2;}  }

int sn_ftpcmd(int fd, int tmo, char* buf, int buflen, const char* strcmd, ...)
{
	va_list arg;
	va_start(arg, strcmd);
	vsprintf(buf, strcmd, arg);
	va_end(arg);
	int r = write_complete(fd, buf, strlen(buf), tmo);
	if (r <= 0){
		printf("write [%s] data err.\n", buf);
		return -1;
	}
	r = get_response(fd, buf, buflen, tmo);
	if (r <= 0){
		printf("read [%s] rep data err.\n", buf);
		return -1;
	}
	return 0;
}
#define FTP_CMD(c,str1,str2)  {  int r = sn_ftpcmd( fd, 12, buf, BUF_SIZE , str1,str2 ); if( r<0){ return -1;}\
						         if(buf[0] != c ){/*printf("ftp cmd error: [%s]\n",buf);*/ return -2;} }
//////////

int ftp_bye(int fd)
{
	char buf[BUF_SIZE];
//	sn_ftpcmd(fd, 10, buf, BUF_SIZE, "QUIT\r\n");

	closesocket(fd);
	return 0;
}


int cn_ftppasv_port(int ctrl_sock, int tmo)
{
	int fd = -1;
	char* start, *end, *ptr, *s_port_hi = 0; int index;
	//	const char sep[]=",";
	int port = 0;
	//
	char buf[1024];
	int r = sn_ftpcmd(ctrl_sock, tmo, buf, 1024, "PASV\r\n");
	if (r < 0)
		return -1;
	if (buf[0] != '2'){
		printf("ftp cmd error: [%s]\n", buf);
		return -1;
	}
	////
	start = strchr(buf, '('); if (!start)goto f_err;
	start += 1;
	end = strchr(start, ')'); if (!end)goto f_err;
	*end = 0;
	index = 0;
	for (ptr = start; *ptr; ++ptr){
		if (*ptr == ','){
			index++;
			if (index == 5){
				//
				if (!s_port_hi)goto f_err;
				int hi = atoi(s_port_hi);
				int lo = atoi(ptr + 1);
				port = hi * 256 + lo;
				break;
			}
			else if (index == 4){
				*ptr = '\0';
				s_port_hi = ptr + 1;
			}
			else if (index < 4)
				*ptr = '.';
		}
	}
	if (index != 5)goto f_err;

	fd = simple_connect(start, port, tmo);
	if (fd < 0) goto f_err;

	return fd;
	///
f_err:
	if (fd != -1)
		closesocket(fd);
	return -1;
}

int ftp_set_current_directory(int fd, const char* remote_curr_dir )
{
	char buf[BUF_SIZE];

	FTP_CMD('2', "CWD %s\r\n", remote_curr_dir);

	return 0; 
}

int ftp_create_directory(int fd, const char* remote_dir)
{
	char buf[1024];
	FTP_CMD('2', "XMKD %s\r\n", remote_dir );

	return 0;
}

int ftp_delete_directory(int fd, const char* remote_dir)
{
	char buf[1024];

	FTP_CMD('2', "RMD %s\r\n", remote_dir );

	return 0;
}

int ftp_delete_file(int fd, const char* remote_path)
{
	char buf[1024];

	FTP_CMD('2', "DELE %s\r\n", remote_path);

	return 0; 
}

int ftp_rename(int fd, const char* old_name, const char* nw_name)
{
	char buf[BUF_SIZE];
	///////

	FTP_CMD('3', "RNFR %s\r\n", old_name); //printf("AAAA\n");
	////
	FTP_CMD('2', "RNTO %s\r\n", nw_name);
	////
	return 0;
}

int ftp_ping(int fd, int tmo, int* out_ms_time)
{
	char buf[512];
	////
	DWORD tick = GetTickCount();
	int r = sn_ftpcmd(fd, tmo, buf, 512, "NOOP\r\n");
	if (out_ms_time)*out_ms_time = GetTickCount() - tick;

	return r<0? -1 : 0;
}

int64_t ftp_get_filesize(int fd, const char* rpath)
{
	char tb[1024];
	tb[0] = 0;
	int r = sn_ftpcmd(fd, 10, tb, BUF_SIZE, "SIZE %s\r\n", rpath );
	if (strncmp(tb, "213", 3) == 0){
		int64_t size = atoll(tb + 4);
		return size;
		////
	}
	return -1;
}

//// FTP List Directory
struct __ftp_list_t
{
	int  ctrl_fd; 
	int  data_fd; 
	char buf[BUF_SIZE];
	int  r_size;

	char ctl_buf[1024];
	int ctl_r_size;
	///
	int  tmo; 
	bool is_end;
	int  result;
	////
	bool single_line;
	ftp_fileinfo_t single_ftpinfo; 

	/////
	list<string> res_str;
};

static void __ftp_close_data_channel(__ftp_list_t* ftpdir)
{
	if (ftpdir->data_fd >= 0){
		////
		closesocket(ftpdir->data_fd);

		int r = read_line(ftpdir->ctrl_fd, ftpdir->ctl_buf, ftpdir->ctl_r_size, 1024, ftpdir->tmo); ////
	//	int r = get_response(ftpdir->ctrl_fd, ftpdir->buf, BUF_SIZE, ftpdir->tmo); //printf("** CLOSE: %s r=%d\n",ftpdir->buf ,r);

		if (ftpdir->ctl_buf[0] != '2'){ // trans error
			///
			r = sn_ftpcmd(ftpdir->ctrl_fd, ftpdir->tmo, ftpdir->buf, BUF_SIZE, "ABOR\r\n");
			ftpdir->result = -1;
		}
		else{
			ftpdir->result = 0; ///
		}

		//////
		ftpdir->data_fd = -1; /// 
	}
	//////
}
int ftp_find_open(int fd, void** phFind, const char* path, const char* option_name, int tmo)
{
	char buf[1024];
	int r;
	int len;
	bool single_line = false; 
	__ftp_list_t* ftpdir = NULL;

	*phFind = NULL;

	r = sn_ftpcmd(fd, tmo, buf, sizeof(buf), "TYPE A\r\n");
	if (r < 0){
		return -1;
	}
	int sc = cn_ftppasv_port(fd, tmo);
	if (sc < 0){
		printf("LIST: get PASV Error [%s].\n",path);
		///
		r = -1; ///
		goto err;
	}
/*	r = sn_ftpcmd(fd, tmo, buf, sizeof(buf), "LIST %s\r\n", path);
	if (r < 0){
		printf("LIST send cmd err [%s].\n",path);
		goto err;
	}
	if (buf[0] != '1'){
		printf("LIST: get response error [%s].\n", path);
		goto err;
	}*/
	///
	
	if (option_name && option_name[0] && //查找名存在
		strchr(option_name, '?') == NULL && strchr(option_name, '*') == NULL) // 没有通配符，说明是正常的文件名字
	{
		////
		sprintf(buf, "LIST %s\r\n", path);
		///////
		single_line = true; // 只查找跟此文件名匹配的信息
	}
	else{
		if (option_name && option_name[0]){
			len = strlen(path); ////
			const char* psep = "/";
			if (len > 0 && path[len - 1] == '/') psep = "";
			bool ff = false; for (int i = 0; option_name[i]; ++i) if (option_name[i] != '*' && option_name[i] != '.'){ ff = true; break; }
			if (!ff)option_name = "";   //printf("*[%s]\n",option_name);
			sprintf(buf, "LIST %s%s%s\r\n", path, psep, option_name ); //包含通配符的查找，直接发到FTP服务器
		}
		else{
			sprintf(buf, "LIST %s\r\n", path);
		}
		//////
	}
	///
	
	r = write_complete(fd, buf, strlen(buf), tmo);
	if (r <= 0){
		r = -1; goto err;
	}
	r = read_line(fd, buf, 0, sizeof(buf), tmo);
	if (r <= 0){
		r = -1; goto err;
	}
	if (buf[0] != '1'){
		printf("LIST: get response error [%s].\n", path);
		r = -2;
		goto err;
	}
	len = strlen(buf) +2 ; ////
	if ( r > len ){ //// 还有剩余的数据,读多了
//		printf("*** [%s]\n", buf+len );
	}
	/////
	ftpdir = new __ftp_list_t;
	ftpdir->ctrl_fd = fd;
	ftpdir->data_fd = sc;
	ftpdir->r_size = 0;
	ftpdir->tmo = tmo;
	ftpdir->is_end = false;
	ftpdir->result = 0;
	ftpdir->ctl_r_size = 0;
	ftpdir->ctl_buf[0] = 0;
	ftpdir->single_line = 0; ///
	if (r > len){
		ftpdir->ctl_r_size = r - len;
		strcpy(ftpdir->ctl_buf, buf + len); /////
	}

	///
	if (single_line){ //只需要一行结果
		bool bFind = false;
		int res;
		while ((res = ftp_find_next(ftpdir, &ftpdir->single_ftpinfo)) > 0 ){ //匹配查找
			if (strcasecmp(ftpdir->single_ftpinfo.name, option_name) == 0){ // find
				bFind = true;
				break;
			}
			//////
		}
		//////
		__ftp_close_data_channel(ftpdir); //关闭数据端口
		
		////////
		if (!bFind){
			ftpdir->single_ftpinfo.name[0] = '\0'; //，没找到
		}

	}

	ftpdir->single_line = single_line; ////
	//////
	*phFind = ftpdir;
	return 0;
	////

err:
	if (sc >= 0)closesocket(sc);
	if (r != -1){
		int rr = sn_ftpcmd(fd, tmo, buf, sizeof(buf), "ABOR\r\n");
		if (rr < 0) return -1;
	}

	return r;
}

int ftp_find_next(void* hfind, ftp_fileinfo_t* info )
{
	__ftp_list_t* ftpdir = (__ftp_list_t*)hfind;
	int r;
	char* line; char* end;
	if (!ftpdir) return -1;
	if (ftpdir->is_end){
		////
		return ftpdir->result; // end 
	}

	/////
	if (ftpdir->single_line){
		
		ftpdir->is_end = true;//

		if (ftpdir->single_ftpinfo.name[0]){
			*info = ftpdir->single_ftpinfo;
			return 1; /// OK 
		}
		else{
			return 0; // not find
		}
	}

	///
	if (ftpdir->res_str.size() > 0){
//		printf("** Next.size=%d\n", ftpdir->res_str.size());
		goto L; ////
	}
	//////
N:	
	while (true){
		///read data
		r = block_read(ftpdir->data_fd, ftpdir->buf + ftpdir->r_size, BUF_SIZE - 1 - ftpdir->r_size, ftpdir->tmo);
		if (r <= 0){
			///
			ftpdir->is_end = true;
			
			////
			__ftp_close_data_channel(ftpdir); /////

			return ftpdir->result;
		}

		/////
		ftpdir->r_size += r;
		ftpdir->buf[ftpdir->r_size] = 0;

		line = ftpdir->buf;
		end = NULL;
		bool bGet = false;
		while ((end = strstr(line, "\r\n")) || (end = strstr(line, "\n")) ){ //也许还得考虑 \n结束的行 2016-03-10
			int sep = 2; if (*end == '\n') sep = 1;
			*end = '\0';
			///
			//	printf("LINE [%s]\n",line );
			ftpdir->res_str.push_back(line); /// 
			bGet = true; ///
			//////
			line = end + sep;
		}
		if (*line != '\0' ){
			ftpdir->r_size = strlen(line);
			strncpy(ftpdir->buf, line, ftpdir->r_size);
		}
		else{
			ftpdir->r_size = 0;
		}
		/////////////
		if (bGet)break; ////
		else if (ftpdir->r_size > BUF_SIZE - 2){//一行太长，不合理
			printf("SHIT ***\n");
			return -1; ///
		}
	}
	/////
L:
	////
	while (ftpdir->res_str.size() > 0){
		struct ftpparse par;
		r = ftpparse(&par, (char*)ftpdir->res_str.front().c_str(), (int)ftpdir->res_str.front().length()); ////

		////
		if (r == 0){//如果格式不对，返回错误; 应该解析下一行，2016-03-10
			ftpdir->res_str.pop_front();
			continue;
		}
		memset(info->name, 0, MAX_PATH);
		strncpy(info->name, par.name, min(MAX_PATH - 1, par.namelen));
		info->is_dir = par.flagtrycwd ? 1 : 0;
		info->file_size = par.size;
		info->attr = 0;
		if (info->is_dir) info->attr = FILE_ATTRIBUTE_DIRECTORY;
		info->mtime = par.mtime;
		///
		ftpdir->res_str.pop_front();
		/////
		return 1;
	}
	////no found
	goto N;
}

int ftp_find_close(void* hfind)
{
	__ftp_list_t* ftpdir = (__ftp_list_t*)hfind;
	if (!ftpdir) return -1;
	///
	if (!ftpdir->is_end){

		__ftp_close_data_channel(ftpdir); ////
		/////
		ftpdir->is_end = true; ///
	}
	////
	delete ftpdir;

	return 0;
}

/////read/write offset data
static int __ftp_readwrite_offset(int fd, const char* path_name, char* buf, int64_t offset, int len, 
	int tmo, bool bRead,
	int(*progress)(int curr_trans, int total_len, void* pram), void* param )
{
	///
	char tb[BUF_SIZE]; 
	char cb[1024];
	int  cb_r_size = 0;
	int r;
	int pos;
	r = sn_ftpcmd(fd, tmo, tb, BUF_SIZE, "TYPE I\r\n");
	if (r < 0) return -1;
/*	if (bRead){
		tb[0] = 0;
		r = sn_ftpcmd(fd, tmo, tb, BUF_SIZE, "SIZE %s\r\n", path_name);
		if (strncmp(tb, "213", 3) == 0){
			int64_t size = atoll(tb + 4);
			if (offset >= size){
				printf("*** FTP offset=%lld >= size=%lld [%s]\n", offset, size, path_name);
				return 0; ///已经越界
			}
			////
		}
	}*/
	///////////////
	r = sn_ftpcmd(fd, tmo, tb, BUF_SIZE, "REST %lld\r\n", offset );
	if (r < 0 || (strncmp(tb, "350", 3) != 0) ) {
		////
		printf("Set File Position error.\n");
		if (r < 0) return -1;
		return -2;
	//	return -1; ///
	}

	/////
	int sc = cn_ftppasv_port(fd, tmo);
	if (sc < 0){
		r = -1;
		printf("read/WRite cn_ftppasv_port err\n");
		goto err;
	}

//	if (bRead) r = sn_ftpcmd(fd, tmo, tb, BUF_SIZE, "RETR %s\r\n", path_name );
//	else r = sn_ftpcmd(fd, tmo, tb, BUF_SIZE, "STOR %s\r\n", path_name );
//	if (r < 0 || tb[0] != '1'){
//		////
//		goto err;
//	}

	sprintf(tb, "%s %s\r\n", bRead ? "RETR" : "STOR", path_name);
	r = write_complete(fd, tb, strlen(tb), tmo);
	if (r <= 0){
		printf("write_complete error\n");
		r = -1;  goto err;
	}
	r = read_line(fd, tb, 0, sizeof(tb), tmo);
	if (r <= 0){
		printf("read_response err\n");
		r = -1;  goto err;
	}
	if (tb[0] != '1'){
		tb[r] = 0;
		printf("Trans file [%s] Error <%s>.\n", path_name, tb );
		r = -2;
		goto err;
	}
	pos = strlen(tb) + 2;
	if (r > pos){ //还有剩余的数据，读多了
		cb_r_size = r - pos;
		strcpy(cb, tb + pos);
	}else {
		cb_r_size = 0;
		cb[0] = 0;
	}
//	printf("%s: [%s],off=%lld,len=%d\n", bRead ? "*R" : "-W", path_name, offset, len);
	/////
	pos = 0; 
	while (pos < len ){
		int DLEN = min( 1024*64, len - pos);
		if (bRead){ r = block_read(sc, buf+pos, DLEN, tmo);}
		else{ r = write_complete(sc, buf + pos, DLEN, tmo);}

		if (r <= 0){
			////
			//if (pos == 0 && bRead ) printf("FTP Recv 0 .\n");
			break;
		}
		
		pos += r;
		//////
		if (progress)progress(pos, len, param); ////
		////////
	}

	closesocket(sc);

//	get_response(fd, tb, BUF_SIZE, tmo);
	read_line(fd, cb, cb_r_size, sizeof(cb), tmo);

	if ( cb[0] != '2' ){
	//	printf("Trasn Abort: [%s]\n", tb);
	//	return -1; /// trans error.
	}
	//////
//	if(bRead) printf("FTP Read off=%lld, len=%d\n", offset, pos);
	return pos; ///

err:
	if (sc >= 0)closesocket(sc);
//	int rr = sn_ftpcmd(fd, tmo, tb, BUF_SIZE, "ABOR\r\n");
//	if (rr < 0) return -1;
	printf("FTP: [%s] [%s] error\n", bRead?"READ":"WRITE", path_name );
    ////
	return r;
}

int ftp_read_offset(int fd, const char* path_name, char* buf, int64_t offset, int len, int tmo,
	int(*progress)(int curr_trans, int total_len, void* pram), void* param)
{
	/////
	return __ftp_readwrite_offset(fd, path_name, buf, offset, len, tmo, true, progress, param );
}

int ftp_write_offset(int fd, const char* path_name, char* buf, int64_t offset, int len, int tmo,
	int(*progress)(int curr_trans, int total_len, void* pram), void* param )
{
	//////
/*	if (offset > 0){ //如果写的位置》0，检测是不是已经超过文件大小，
		int64_t size = ftp_get_filesize(fd, path_name); //获取文件长度
		if (size < offset){
			printf("[%s] size=%lld, offset=%lld\n", path_name, size, offset );
			if (size < 0) size = 0;

			char* bb; // 
			int BUFSIZE = min(1024 * 512, offset-size );
			bb = (char*)malloc(BUFSIZE);
			memset(bb, 0, BUFSIZE);
			while (size < offset){
				int rd_len = min(BUFSIZE, offset - size); if (rd_len <= 0)break; 
				int ret = __ftp_readwrite_offset(fd, path_name, bb, size, rd_len, tmo, false);
				if (ret <= 0){
					break;
				}
				size += ret; 
			}
			free(bb);
		}
		//////
	}*/

	int r =  __ftp_readwrite_offset(fd, path_name, buf, offset, len, tmo, false, progress, param );
//	printf("FTP Write: [%s] offset=%lld, len=%d, ret_len=%d\n", path_name, offset, len, r );
	return r;
}

int ftp_stat(int fd, const char* path_name, ftp_fileinfo_t* info , int timeout )
{
	int r;
	if (strcmp(path_name, "/") == 0){ // root dir
		info->mtime = time(0);
		info->is_dir = true;
		info->attr = FILE_ATTRIBUTE_DIRECTORY; 
		strcpy(info->name, "/");
		info->file_size = 0;
		return 0;
	}
	const char* name = strrchr(path_name, '/'); if (!name)return -1; name += 1;
	r = ftp_set_current_directory( fd, path_name );
	ftp_set_current_directory(fd, "/");

	if (r == 0){ ////说明是个目录
		info->mtime = time(0); //乱写的一个时间
		info->attr = FILE_ATTRIBUTE_DIRECTORY;
		info->file_size = 0;
		info->is_dir = true;
		strcpy(info->name, name); ////
		return 0;
	}
	/////
	/////可能是文件或者不存在
/*	void* find = 0;
	r = ftp_find_open(fd, &find, path_name, "", timeout);
	if ( r != 0 ){
		printf("getFileInfo [%s] not open find ret=%d.\n", path_name , r );
		return r;
	}
	int ff = ftp_find_next(find, info); //printf("** getFileinfo ftp_find_next [%s] sz=%lld,dir=%d,ret=%d \n", path,info->file_size,info->is_dir,ff );
	ftp_find_close(find);

	r = 0;
	if (ff == 0)r = -2; 
	else if (ff > 0) r = 0;
	else r = -1;*/
	char dir[512]; 
	strncpy(dir, path_name, name - path_name);
	dir[name - path_name] = '\0';
	void* hfind = 0;
	r = ftp_find_open(fd, &hfind, dir, "", timeout);
	if (r != 0){
		printf("getFileInfo [%s] not open find ret=%d.\n", path_name, r);
		return r;
	}
	while ( (r = ftp_find_next(hfind, info)) > 0){
		if (strcasecmp(name, info->name) == 0){
			////
			break;
		}
	}
	ftp_find_close(hfind);

	if (r > 0) r = 0;
	else if (r < 0) r = -1;
	else if (r == 0) r = -2;

	return r;
}

///设置服务端文件长度，这个命令，在FTP不好模拟，现在只是解决新长度大于原始长度，可以新加一些数据到尾部，但是如果新长度小于原始长度，没法设置
int ftp_set_newsize(int fd, const char* rpath, int64_t newsize, int timeout )
{
	///
	if (newsize > 0){
		printf("FTP: not Randomly Access. [%s] newsize=%lld\n", rpath, newsize);
		return 0;
	}
	/////
	int r=-1;
	int64_t size = ftp_get_filesize(fd, rpath);

	if (newsize <= 0){
		if (size > 0){
			printf("*** ftp_set_newsize: [%s] newsize[%lld] < filesize[%lld]\n", rpath, newsize, size );
			return -2; ///
		}
		char buf[10];
		r = ftp_write_offset(fd, rpath, buf, newsize, 0, timeout, NULL, 0 );
		return r;
	}
	/////
	if (size < 0){
		size = 0;
	}
	if (newsize == size) return 0;
	if (newsize < size){
		printf("*** ftp_set_newsize: [%s] newsize[%lld] < filesize[%lld]\n", rpath, newsize, size);
		return -2; ///
	}

	char buf[10];
	r = ftp_write_offset(fd, rpath, buf, newsize, 0, timeout, NULL, 0);
	return r; 
}

///////////////////////
#if 0

int main(int argc, char** argv)
{
	WSADATA d; WSAStartup(0x0202, &d);
	int r;
	////
	int fd = ftp_login("192.168.88.120", 21, "anonymous", "", 10);
//	int fd = ftp_login("192.168.88.6", 21, "fxs", "123", 10);

	char buffer[1000];
//	r = ftp_write_offset(fd, "/1/stor.txt", buffer, 0, 10, 10);
//	r = ftp_write_offset(fd, "/1/stor.txt", buffer, 100, 20, 10);
	//r = ftp_set_newsize(fd, "/99/stor.txt", 450, 10);

	ftp_fileinfo_t st;
	r = ftp_stat(fd, "/123.mp3", &st, 10);

	void* hfind = 0; ftp_find_open(fd, &hfind, "/", "*", 10);

	ftp_fileinfo_t info;
	r = ftp_find_next(hfind, &info);
	r = ftp_find_close(hfind);
//	printf("\n\n");
	ftp_find_open(fd, &hfind, "/", "", 10);
	while ( (r = ftp_find_next(hfind, &info)) > 0){
		////
		printf("[%s]  %lld %s\n", info.name, info.file_size, info.is_dir?"DIR":"FILE");
	}
	ftp_find_close(hfind);
	////
	char* buf = (char*)malloc(1024 * 1024);

	while ((r = ftp_read_offset(fd, "/1080P.wmv", buf, 0, 1024 * 64, 10)) > 0){
	//	ftp_bye(fd);
	//	fd = ftp_login("192.168.100.1", 21, "anonymous", "", 10);
	}
	printf("Ret=%d\n",r);
	//////
	ftp_bye(fd);
	////
	WSACleanup();

	return 0; 
}

#endif
