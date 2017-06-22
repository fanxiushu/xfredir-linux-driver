/////by fanxiushu 2016-07-29
#include "xfs_redir.h"
#include "ioctl.h"

#define XFS_CDO_NAME   "xfsredir"

int xfs_cdo_open(struct inode* ino, struct file* fp);
int xfs_cdo_release(struct inode* ino, struct file* fp);
ssize_t xfs_cdo_read(struct file* fp, char* buf, size_t length, loff_t* offset);
ssize_t xfs_cdo_write(struct file* fp, const char* buf, size_t length, loff_t* offset);
unsigned int xfs_cdo_poll(struct file *fp, poll_table *wait);
#if LINUX_VERSION_CODE >= MIN_KVER
long xfs_cdo_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);
#else
long xfs_cdo_ioctl(struct inode* inode, struct file *fp, unsigned int cmd, unsigned long arg);
#endif

///
int __begin_parse_op_queue(struct mon_dir_t* md, struct op_queue_t* op,
	char* user_buffer, size_t length);
int __end_parse_op_queue(struct mon_dir_t* md, 
	const char* user_buffer, size_t length);

/////
static struct file_operations xfs_cdo_fops = {
	.open = xfs_cdo_open,
	.release = xfs_cdo_release,
	.read = xfs_cdo_read,
	.write = xfs_cdo_write,
#if LINUX_VERSION_CODE >= MIN_KVER
	.unlocked_ioctl = xfs_cdo_ioctl,
#else
	.ioctl = xfs_cdo_ioctl,
#endif
	.poll = xfs_cdo_poll,
};

int cdo_init()
{
	int result;
	dev_t devt;
	char tmp_str[30];
	struct device* xfs_dev;

	devt = MKDEV(xfs->cdo_major, 0);
	if (xfs->cdo_major) {
		result = register_chrdev_region(devt, 1, XFS_CDO_NAME);
	}
	else {
		result = alloc_chrdev_region(&devt, 0, 1, XFS_CDO_NAME);
		xfs->cdo_major = MAJOR(devt);
	}
	if (result < 0) {
		printk(KERN_ALERT"register Device ID Error.\n");
		return result;
	}
	
	/////
	cdev_init(&xfs->cdo_dev, &xfs_cdo_fops); ////
	xfs->cdo_dev.owner = THIS_MODULE;
	xfs->cdo_dev.ops = &xfs_cdo_fops;

	result = cdev_add(&xfs->cdo_dev, devt, 1);
	if (result < 0) {
		printk("cdev_add err=%d\n", result);
		unregister_chrdev_region(devt, 1);
		return result;
	}

	///创建设备节点，为了用户程序能访问
	sprintf(tmp_str, "cls_xfsredir" );
	xfs->cdo_cls = class_create(THIS_MODULE, tmp_str);
	if (IS_ERR(xfs->cdo_cls) ) {
		///
		result = PTR_ERR(xfs->cdo_cls);
		xfs->cdo_cls = NULL;
		printk(KERN_ALERT"class_create err =%d\n" , result );
		goto E;
	}
	xfs_dev = device_create(xfs->cdo_cls, NULL, devt, NULL, XFS_CDO_NAME);
	if ( IS_ERR(xfs_dev) ) {
		result = PTR_ERR(xfs_dev);
		printk(KERN_ALERT"device_create err=%d\n", result);
		goto E;
	}

	return 0;
	//////
E:
	cdev_del(&xfs->cdo_dev);

	if (xfs->cdo_cls) {
		device_destroy(xfs->cdo_cls, devt);
		class_destroy(xfs->cdo_cls);
		xfs->cdo_cls = NULL;
	}

	unregister_chrdev_region(devt, 1);

	return result;
}

void cdo_deinit()
{
	dev_t devt;
	devt = MKDEV(xfs->cdo_major, 0);

	if (xfs->cdo_cls) {
		//
		cdev_del(&xfs->cdo_dev);
		////
		device_destroy(xfs->cdo_cls, devt);
		class_destroy(xfs->cdo_cls);
		xfs->cdo_cls = NULL;

		////
		unregister_chrdev_region(devt, 1);
	}
	//////
}

/////////////////////
///字符设备读写
int xfs_cdo_open(struct inode* ino, struct file* fp)
{
	///
	fp->private_data = NULL; /// -> mon_dir_t 

	printk(KERN_NOTICE"xfs_cdo_open\n" );
	return 0;
}

int xfs_cdo_release(struct inode* ino, struct file* fp)
{
	/////
	int ret = 0;
	struct mon_dir_t* md = (struct mon_dir_t*)fp->private_data;

	if (md) {

		char dir[256];
		strcpy(dir, md->path.buffer); 

		printk("xfs_cdo_release: destroy_monitor_directory: [%s]\n", md->path.buffer );
		destroy_monitor_directory(md);

		fp->private_data = NULL; ///

		/////
	}

	return ret;
}

/// read & write 
ssize_t xfs_cdo_read(struct file* fp, char* buf, size_t length, loff_t* offset)
{
	struct mon_dir_t* md = (struct mon_dir_t*)fp->private_data;
	int ret = -1;
	
	DECLARE_WAITQUEUE(wait, current); //申明一个等待队列

	if (!md)return -EINVAL;
								  
	////
	add_wait_queue(&md->wait_q, &wait); //加入到等待队列

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);  //设置进程可休眠状态

		lock();
		if ( !list_empty(&md->wait_head) ) { //有数据可读
			struct list_head* entry = md->wait_head.next;
			
			struct op_queue_t* op = list_entry(entry, struct op_queue_t, list);

			////
			op->is_nobuffer = 0; 
			ret = __begin_parse_op_queue(md, op, buf, length);

			if (op->is_noreply) { //不需要从应用层返回

				__op_queue_complete(op, op->ret); ////
				/////
			}
			else if (op->is_nobuffer) { //__begin_parse_op_queue 处理时候，user_buffer空间不够
				///
				op->is_nobuffer = 0; ////
				ret = sizeof(struct ioctl_oparg_t);
				////
			}
			else if (ret > 0) { // success

				list_move_tail(entry, &md->busy_head ); //成功，添加到忙碌队列
			}
			else {
				///
				if (ret == 0)ret = -EINVAL; //读取长度，起码是 sizeof(struct ioctl_oparg_t); 

				__op_queue_complete(op, ret); ////

			}
			//////
			

			unlock();
			break;
		}
		unlock();

		///
		if (fp->f_flags & O_NONBLOCK) { //非阻塞状态
			ret = -EAGAIN;
			printk("xfs_cdo_read: O_NONBLOCK read return now\n");
			break;
		}
		////
		if (signal_pending(current)) { //进程被信号中断
			ret = -ERESTARTSYS;
			printk("xfs_cdo_read: INTR read \n");
			break;
		}
		/////其他状态，什么都不做，调用schudle休眠
		printk("xfs_cdo_read: schedule.\n");
		schedule();

	}

	set_current_state(TASK_RUNNING); //设置进程可运行
	remove_wait_queue(&md->wait_q, &wait); //移除出等待队列

    ////
	return ret;
}

ssize_t xfs_cdo_write(struct file* fp, const char* buf, size_t length, loff_t* offset)
{
	struct mon_dir_t* md = (struct mon_dir_t*)fp->private_data;
	int ret = -EINVAL;

	if (!md) {
		return -EINVAL;
	}
	////
	lock();
	ret = __end_parse_op_queue(md, buf, length); 
	unlock();

	return ret;
}

////////
static long msec_to_jiffies(long msec)
{
	struct timespec tmo;
	if (msec == 0)return 0; 
	tmo.tv_sec = msec / 1000;
	tmo.tv_nsec = (msec % 1000)*(1000*1000);
	return timespec_to_jiffies(&tmo);
}
#if LINUX_VERSION_CODE >= MIN_KVER
long xfs_cdo_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
#else
long xfs_cdo_ioctl(struct inode* inode, struct file *fp, unsigned int cmd, unsigned long arg)
#endif
{
	int ret = -EINVAL;
	struct mon_dir_t* md = (struct mon_dir_t*)fp->private_data;
	printk(KERN_ALERT"xfs_cdo_ioctl cmd=0x%x\n" , cmd );

	// 首先检查cmd是否合法
	if (_IOC_TYPE(cmd) != IOCTL_MAGIC) return -EINVAL;
	//if (_IOC_NR(cmd) > NEWCHAR_IOC_MAXNR) return -EINVAL;

	switch (cmd)
	{
	case IOCTL_SET_MON_DIR:
		{
			struct ioctl_mondir_t ct; 
			
			if (md != NULL) {
				printk("IOCTL_SET_MON_DIR: had set mondir.\n");
				return -EEXIST;
			}
			///
			
			if (copy_from_user(&ct, (const char*)arg, sizeof(ct)) != 0) return -EFAULT;

			ret = create_monitor_directory(ct.mon_dir, &md);
			if (ret == 0) { // success
				/////

				md->root_ino = ct.root_ino; 
				md->root_uid = ct.root_uid;
				md->root_gid = ct.root_gid; 
				///
				md->q_tmo = msec_to_jiffies(ct.query_tmo);
				md->t_tmo = msec_to_jiffies(ct.trans_tmo) ;

				md->e_tmo = msec_to_jiffies(ct.entry_tmo);
				md->a_tmo = msec_to_jiffies(ct.attr_tmo);

				md->is_dio = ct.is_direct_io; ////
				//////////////////
				fp->private_data = md; ///

			}
			else{
				printk("create_monitor_directory [%s] err=%d\n", ct.mon_dir, ret );
			}
			/////
		}
		break;

	case IOCTL_POLL_NOWAIT: //
		ret = 0;
		if (md) {
			lock();
			md->is_poll_nowait = 1;
			wake_up_interruptible(&md->wait_q); //通知用户进程，有新的请求, 用户端select或者poll立马返回
			unlock();
		}
		break;

	case IOCTL_CLEAR_INODE_USRCTX:
		ret = -EINVAL;
		if (md) {
			u64 ino = 0;
			if (copy_from_user(&ino, (const char*)arg, sizeof(u64)) != 0) return -EFAULT;
			////
			ret = xfs_clear_inode_usrctx(md, ino);
			//////
		}
		break;
	}
	return ret;
}

unsigned int xfs_cdo_poll(struct file *fp, poll_table *wait)
{
	struct mon_dir_t* md = (struct mon_dir_t*)fp->private_data;
	////
	int mask = POLLOUT | POLLWRNORM; //随时可写
	if (!md) {
		return (POLLOUT | POLLWRNORM | POLLIN | POLLRDNORM);
	}

	////
	lock();
	
	poll_wait(fp, &md->wait_q, wait); //把等待队列加到wait中，函数立即返回 

	if ( !list_empty(&md->wait_head) || md->is_poll_nowait ) //有数据可读
		mask |= POLLIN | POLLRDNORM;

	unlock();

	///
	return mask;
}

///返回传输数据长度
int __begin_parse_op_queue(struct mon_dir_t* md, struct op_queue_t* op,
	char* user_buffer, size_t length )
{
	int ret ;
	struct xfs_inode_t* xi;
	struct ioctl_oparg_t oparg;

	if (length < sizeof(struct ioctl_oparg_t)) {
		op->ret = -EINVAL;
		return op->ret;
	}
	ret = sizeof(struct ioctl_oparg_t);
	xi = XFS_INODE(op->inode);
	///
	oparg.inter_handle = (uint64_t)op->inode;
	op->inter_seqno = xfs->seq_no++;
	oparg.inter_seqno = op->inter_seqno;
	oparg.op_type = op->op_type;
	oparg.i_ino = op->inode->i_ino;  ////
	oparg.length = 0; 
	oparg.ret = 0; 

	oparg.user_pid = xi->user_pid;
	oparg.i_usrctx  = xi->i_usrctx;
	oparg.i_usrctx2 = xi->i_usrctx2;
	/////
//	printk("__begin_parse_op_queue: op_type=%d, ino=%ld\n", op->op_type, op->inode->i_ino );

	switch (op->op_type)
	{
	case OP_LOOKUP:
	case OP_QUERY_STAT:
		{
			///
			if(op->dentry) { // OP_LOOKUP
				ret += (op->dentry->d_name.len + 1 );
				if (length < ret) {
					printk("*** user_buffer too small.\n");
					return -EINVAL;
				}
				oparg.length = op->dentry->d_name.len + 1; ///
				///
			}
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0 ) {
				///
				return -EFAULT; ///
			}
			if (op->dentry) {
				////复制需要查询的文件名
				if (copy_to_user( user_buffer + sizeof(oparg), op->dentry->d_name.name, op->dentry->d_name.len + 1) != 0) {
					printk("copy_to_user err\n");
					return -EFAULT;
				}
			}
			//////
		}
		break;

	case OP_SET_STAT:
		{
			////
			ret += sizeof(struct file_stat_t);
			oparg.length = sizeof(struct file_stat_t);
			if (length < ret) {
				return -EINVAL;
			}
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0) {
				///
				return -EFAULT; ///
			}
			if (copy_to_user(user_buffer + sizeof(oparg), op->stat, sizeof(struct file_stat_t )) != 0) {
				///
				return -EFAULT; ///
			}
			//////
		}
		break;

	case OP_READDIR:
		{
			////
			oparg.readdir.d_id = (u64)op->readdir.fp;
			oparg.readdir.d_usrctx = op->readdir.fp->d_usrctx;
			oparg.readdir.d_usrctx2 = op->readdir.fp->d_usrctx2;
			oparg.readdir.is_end = 0;
			if (op->is_noreply) {
				op->ret = 0;
				oparg.readdir.is_end = 1; /// end 
			}

			////
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0) {
				///
				return -EFAULT; ///
			}
			/////
		}
		break;

	case OP_MKNOD:
	case OP_RMNOD:
		{
			if(op->op_type == OP_MKNOD) oparg.mknod.mode = op->mknod.mode;
			else oparg.rmnod.is_rmdir = op->rmnod.is_rmdir; ////
			///
			ret += (op->dentry->d_name.len + 1);
			if (length < ret) {
				printk("*** user_buffer too small.\n");
				return -EINVAL;
			}
			oparg.length = op->dentry->d_name.len + 1; ///

			////
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0) {
				///
				return -EFAULT; ///
			}
			////
			////复制需要创建的文件名
			if (copy_to_user(user_buffer + sizeof(oparg), op->dentry->d_name.name, op->dentry->d_name.len + 1) != 0) {
				printk("copy_to_user err\n");
				return -EFAULT;
			}
			//////
		}
		break;

	case OP_RENAME:
		{
			////
			oparg.rename.newdir_ino = op->rename.new_dir->i_ino; ///
			////
			ret += (op->dentry->d_name.len + 1) + (op->rename.new_dentry->d_name.len + 1); /// old_name -> new_name 
			if (length < ret) {
				printk("*** user_buffer too small.\n");
				return -EINVAL;
			}
			oparg.length = (op->dentry->d_name.len + 1) + (op->rename.new_dentry->d_name.len + 1) ; ///
			/////
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0) {
				///
				return -EFAULT; ///
			}
			////
			////copy old_name
			if (copy_to_user(user_buffer + sizeof(oparg), op->dentry->d_name.name, op->dentry->d_name.len + 1) != 0) {
				printk("copy_to_user err\n");
				return -EFAULT;
			}
			/// copy new_name 
			if (copy_to_user(user_buffer + sizeof(oparg) + op->dentry->d_name.len + 1 , 
				  op->rename.new_dentry->d_name.name, op->rename.new_dentry->d_name.len + 1) != 0) {
				printk("copy_to_user err\n");
				return -EFAULT;
			}
			////
		}
		break;

	case OP_READ:
		{
			/////
			oparg.readwrite.offset = op->readwrite.offset;
			oparg.readwrite.length = op->readwrite.length;
			////
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0) {
				///
				return -EFAULT; ///
			}
			/////

		}
		break;

	case OP_WRITE:
		{
			/////
			oparg.readwrite.offset = op->readwrite.offset;
			oparg.readwrite.length = op->readwrite.length;
			oparg.length = op->readwrite.length; 
			////
			if (copy_to_user(user_buffer, &oparg, sizeof(oparg)) != 0) {
				///
				return -EFAULT; ///
			}
			/////
			ret += op->readwrite.length;
			if (length < ret) {
				op->is_nobuffer = 1; //应用层将重新解析
				ret = sizeof(oparg);
				break;
			}
			/////
			if (op->readwrite.pages) { //页方式copy数据
				/////
				size_t copied = xfs_copy_user_with_pages(op->readwrite.pages, user_buffer + sizeof(oparg),
					op->readwrite.length, 1 );
				if (copied != op->readwrite.length) {
					printk("***** IOCTL: OP_WRITE xfs_copy_user_with_pages not copy data copied=%ld, req_len=%ld\n", copied, op->readwrite.length );
					return -EFAULT; ///
				}
				//////
			}
			else {
				/////
				if (copy_to_user(user_buffer + sizeof(oparg), op->readwrite.buffer, op->readwrite.length) != 0) {
					////
					return -EFAULT;
				}
				//////
			}
			////////
		}
		break;

	}
	return ret;
}

///返回传输数据长度
int __end_parse_op_queue(struct mon_dir_t* md, 
	const char* user_buffer, size_t length)
{
	struct op_queue_t* op;
	struct op_queue_t* pos;
	int ret = -EINVAL;
	int ret_len = sizeof(struct ioctl_oparg_t); //
	struct ioctl_oparg_t oparg; 
	struct xfs_inode_t* xi;

	if (length < sizeof(struct ioctl_oparg_t)) {
		return -EINVAL;
	}
	/////
	if (copy_from_user( &oparg, user_buffer, sizeof(oparg)) != 0 ) {
		/// bad address.
		return -EFAULT;
	}
	///////////
	op = NULL;
	list_for_each_entry(pos, &md->busy_head, list ) { //从忙碌队列取出数据
		if (oparg.inter_handle == (u64)pos->inode && 
			oparg.inter_seqno == pos->inter_seqno && 
			oparg.op_type == pos->op_type ) 
		{
			op = pos; 
			break;
		}
	}
	if (!op) {
		return -ENOENT; ////
	}
	
	///
	xi = XFS_INODE(op->inode);
	////
	if ( !op->is_clear_inode_usrctx ) {
		xi->user_pid = oparg.user_pid;
		xi->i_usrctx = oparg.i_usrctx;
		xi->i_usrctx2 = oparg.i_usrctx2;
	}

	//////
	ret = oparg.ret;
	if (ret != 0) { //应用层返回失败
		if (ret > 0) ret = -ret;
		///
		__op_queue_complete(op, ret); ////完成

		return ret; 
	}

	//// end parse
	switch (oparg.op_type)
	{
	case OP_LOOKUP:
	case OP_QUERY_STAT:
	case OP_MKNOD:
		{
			///
			if (length < sizeof(oparg) + sizeof(struct file_stat_t)) {
				ret = -EINVAL;
				break;
			}

			if (copy_from_user( op->stat, user_buffer + sizeof(oparg), sizeof(struct file_stat_t)) != 0 ) {
				ret = -EFAULT;
				break;
			}
			////
			ret_len += sizeof(struct file_stat_t); ///
		}
		break;

	case OP_SET_STAT:
		break;
	case OP_RMNOD:
		break; 
	case OP_RENAME:
		break;

	case OP_READDIR:
		{
			op->readdir.fp->d_usrctx = oparg.readdir.d_usrctx;
			op->readdir.fp->d_usrctx2 = oparg.readdir.d_usrctx2;
			if (oparg.readdir.is_end) {
				op->readdir.fill->name_len = 0;
				op->readdir.fill->name[0] = 0;
				///
				break;
			}
			/////
			if (length < sizeof(oparg) + sizeof(struct file_dirfill_t)) {
				ret = -EINVAL;
				break;
			}

			if (copy_from_user(op->readdir.fill, user_buffer + sizeof(oparg), sizeof(struct file_dirfill_t)) != 0) {
				ret = -EFAULT;
				break;
			}
			op->readdir.fill->name[255] = 0;
			if (op->readdir.fill->name_len > 255) op->readdir.fill->name_len = 255; ///

			///
			if (strcmp(op->readdir.fill->name, ".") == 0 || strcmp(op->readdir.fill->name, "..") == 0) {
				printk("__end_parse_op_queue: OP_READDIR name[.][..] not complete the op.\n");
				///
				list_move(&op->list, &md->wait_head); ///从忙碌队列移除，重新加入到等待队列
				////
				return -EEXIST;
			}
			////
			ret_len += sizeof(struct file_dirfill_t); ///


		}
		break;

	case OP_READ:
		{
			////
			if (oparg.length > op->readwrite.length) { //这是不应该发生的 
				ret = -EINVAL;
				break;
			}

			ret = oparg.length; ///读取长度
			if (ret <= 0) {
				break;
			}

			/////
			if (op->readwrite.pages) { /////按照页方式读取
				if (xfs_copy_user_with_pages(op->readwrite.pages, (char*)user_buffer + sizeof(oparg), ret, 0) != ret ){
				    //////
					ret = -EFAULT;
					printk("IOCTL: OP_READ xfs_copy_user_with_pages not copied all data \n");
					break;
				}
			}
			else{ ////
				if (copy_from_user(op->readwrite.buffer, user_buffer + sizeof(oparg), ret) != 0) {
					ret = -EFAULT;
					break;
				}
			}
			/////

		///////
		}
		break;

	case OP_WRITE:
		{
			////
			if (oparg.length > op->readwrite.length) { //这是不应该发生的 
				ret = -EINVAL;
				break;
			}

			ret = oparg.length; ///实际写入的长度
			//////
		}
		break;
	}

	/////

	__op_queue_complete(op, ret); ////完成

	return ret < 0 ? ret : ret_len;
}

