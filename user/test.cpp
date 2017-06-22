////
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char** argv)
{
//	DIR* d = opendir("/home/xfsredir/mon_dir"); if (!d)exit(0);
	char buf[1024 * 1024];
	int fd = open("/home/xfsredir/mon_dir/Music/she-zh.mp3", O_RDONLY );
	if (fd < 0) { printf("open err=%d\n", errno ); }
	lseek(fd, 1234560, SEEK_SET);
	int r = read(fd, buf, sizeof(buf));
	close(fd);
	printf("read = %d\n", r );
	return 0;
}

