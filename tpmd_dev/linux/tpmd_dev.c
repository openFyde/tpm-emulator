#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/un.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/wait.h>
#include <linux/version.h>
#include "tpm_tis_core.h"
#include "config.h"

#define CLASS_NAME "tpmd_dev"
#define TPM_DEVICE_MINOR  MISC_DYNAMIC_MINOR
#define TPM_DEVICE_ID  "vtpm"
#define TPM_READY_SIG "ready"
#define TPM_TAG_RSP_COMMAND             0x00C4
#define TPM_ORD_GET_CAP 101

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mario Strasser <mast@gmx.net>, Yang Tsao <yang@flintos.io>");
MODULE_DESCRIPTION("Trusted Platform Module (TPM) Emulator");
MODULE_SUPPORTED_DEVICE(CLASS_NAME);

char *tpmd_socket_name = TPM_SOCKET_NAME;
module_param(tpmd_socket_name, charp, 0444);
MODULE_PARM_DESC(tpmd_socket_name, " Sets the name of the TPM daemon socket.");

#define error(fmt, ...) printk(KERN_ERR "%s %s:%d: Error: " fmt "\n", \
                        CLASS_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
#define info(fmt, ...)  printk(KERN_INFO "%s %s:%d: Info: " fmt "\n", \
                        CLASS_NAME, __FILE__, __LINE__, ## __VA_ARGS__)
enum tpm_const_fydeos {
    TPM_TIMEOUT_A		= 750,
	TPM_TIMEOUT_B		= 2000,
	TPM_TIMEOUT_C		= 200,
	TPM_TIMEOUT_D		= 30,
    TPM_DURATION_SHORT	= 20,
	TPM_DURATION_MEDIUM	= 750,
	TPM_DURATION_LONG	= 2000,
};
struct tpm_emulator_phy {
    struct socket *tpmd_sock;
    struct mutex emulator_mutex;
	  struct tpm_tis_data priv;
	  struct device *dev;
    struct sockaddr_un sock_addr;
    u8 buf[TPM_CMD_BUF_SIZE];
    u16 header_index;
    u16 tail_index;
};

struct tpm_command_get_prop {
  struct tpm_input_header header;
  __be32 cmd_type;
  __be32 space;
  __be32 prop;  
};

struct tpm_command_ret_prop {
  struct tpm_output_header header;
  __be32 space;
  cap_t cap;
};

u8 _status = 0x0;
u8 _access = 0x0;

struct tpm_emulator_phy *phy;

static int tpmd_connect(char *socket_name)
{
  int res;
  res = sock_create(PF_UNIX, SOCK_STREAM, 0, &phy->tpmd_sock);
  if (res != 0) {
    dev_err(phy->dev, "sock_create() failed: %d\n", res);
    phy->tpmd_sock = NULL;
    return res;
  }
  phy->sock_addr.sun_family = AF_UNIX;
  strncpy(phy->sock_addr.sun_path, socket_name, sizeof(phy->sock_addr.sun_path)-1);
  res = phy->tpmd_sock->ops->connect(phy->tpmd_sock,
    (struct sockaddr*) &phy->sock_addr, sizeof(struct sockaddr_un), 0);
  if (res != 0) {
    dev_err(phy->dev, "sock_connect() failed: %d\n", res);
    phy->tpmd_sock->ops->release(phy->tpmd_sock);
    phy->tpmd_sock = NULL;
  }
  return res;
}

static void tpmd_disconnect(void)
{
  if (phy->tpmd_sock) phy->tpmd_sock->ops->release(phy->tpmd_sock);
  phy->tpmd_sock = NULL;
}

static void set_access_prop_ready(void){
  _access |= TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID;
}

static void inactive_locality(void){
  _access = TPM_ACCESS_VALID;
}

static u8 get_access_prop(void) {return _access;}
static u8 get_status_prop(void) {return _status;}
static void set_command_ready(void){
  _status |= TPM_STS_COMMAND_READY;
}
static void unset_command_ready(void) {
  _status &= ~TPM_STS_COMMAND_READY;
}
static void set_data_avalible(void) {
  _status |= TPM_STS_DATA_AVAIL;
}
/*
static void unset_data_avalible(void) {
  _status &= ~TPM_STS_DATA_AVAIL;
}
*/
static void set_sts_valid(void){
  _status |= TPM_STS_VALID;
}
static void set_data_expect(void){
  _status |= TPM_STS_DATA_EXPECT;
}
static void unset_data_expect(void){
  _status &= ~TPM_STS_DATA_EXPECT;
}
static u32 get_vid (void) {return TPM_VID_INTEL;}
static u8 get_rid (void){return 1;}
static u32 get_caps (void) {return TPM_INTF_BURST_COUNT_STATIC;}
static u32 get_bust_count(void){return TPM_CMD_BUF_SIZE;}
static void reset_buf(void){
  if (phy){
    phy->header_index = 0;
    phy->tail_index = 0;
  }
}
static u16 get_buf_length(void) {
  if (phy){
    return phy->tail_index - phy->header_index;
  }
  return 0;
}
static int push_data(const u8 *in, u16 len) {
  u16 count=0;
  if (!phy || len == 0) return -1;
  if (len > (TPM_CMD_BUF_SIZE - phy->tail_index)) return -1;
  while(count < len){
    phy->buf[phy->tail_index++]=in[count++];
  }
  if (len == 1)  {
    unset_data_expect();
  } else {
    set_data_expect();
  }
  set_sts_valid();
  return 0;
}

static void reset_phy(void) {
  if (!phy) return;
  _status = 0;
  _access = 0;
  reset_buf();
  set_command_ready();
  set_access_prop_ready();
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,12,1)
  phy->priv.flags |= TPM_TIS_ITPM_POSSIBLE;
#else
  phy->priv.flags |= TPM_TIS_ITPM_WORKAROUND;
#endif

}

static int fetch_data(u8 *out, u16 len) {
  u16 count=0;
  if (!phy) return -1;
  if (len > get_buf_length())
    len = get_buf_length();
  while (count < len){
    out[count++]=phy->buf[phy->header_index++];
  }
  if (phy->header_index == phy->tail_index) {
    reset_phy();
  }
  set_sts_valid();
  return 0;
}

static void on_handle_begin(void) {
  unset_command_ready();
}

static void on_handle_send_complete(void){
  reset_buf();
}

static void on_handle_recv_complete(void) {
  set_data_avalible();
}

static void on_handle_error(void) {
  reset_phy();
}

static bool is_request_cap(void) {
  const struct tpm_command_get_prop *cmd = (const struct tpm_command_get_prop *) phy->buf;
  if (get_buf_length() < TPM_HEADER_SIZE + 12)
      return false;
  return cmd->header.tag == cpu_to_be16(TPM_TAG_RQU_COMMAND) &&
      cmd->header.ordinal == cpu_to_be32(TPM_ORD_GET_CAP) &&
      cmd->cmd_type == cpu_to_be32(TPM_CAP_PROP);
}

static u32 get_req_cmd(void) {
  const struct tpm_command_get_prop *cmd = (const struct tpm_command_get_prop *)phy->buf;
  return be32_to_cpu(cmd->prop);
}

static bool can_handle_prop_req(u32 req) {
  return req == TPM_CAP_PROP_TIS_TIMEOUT || 
           req == TPM_CAP_PROP_TIS_DURATION;
}


static int handle_prop_req(u32 req) {
  struct tpm_command_ret_prop *buf =(struct tpm_command_ret_prop *) phy->buf;
  on_handle_begin();
  on_handle_send_complete();
  buf->header.tag = cpu_to_be16(TPM_TAG_RSP_COMMAND);
  switch (req) {
    case TPM_CAP_PROP_TIS_TIMEOUT:
      buf->cap.timeout.a = cpu_to_be32(TPM_TIMEOUT_A);
      buf->cap.timeout.b = cpu_to_be32(TPM_TIMEOUT_B);
      buf->cap.timeout.c = cpu_to_be32(TPM_TIMEOUT_C);
      buf->cap.timeout.d = cpu_to_be32(TPM_TIMEOUT_D);
      break;
    case TPM_CAP_PROP_TIS_DURATION:
      buf->cap.duration.tpm_short = cpu_to_be32(TPM_DURATION_SHORT);
      buf->cap.duration.tpm_medium = cpu_to_be32(TPM_DURATION_MEDIUM);
      buf->cap.duration.tpm_long = cpu_to_be32(TPM_DURATION_LONG);
      break;
    default:
	  on_handle_error();
	  return -1;
  }
  phy->tail_index = sizeof(*buf); 
  on_handle_recv_complete();
  return 0; 
}

static int tpmd_handle_command(void){
  int res;
  mm_segment_t oldmm;
  struct msghdr msg;
  struct iovec iov;
  oldmm = get_fs();
  set_fs(KERNEL_DS);
  if (!phy) return -1;
  if (get_buf_length() < 1) return -1;
  /* send command to tpmd */
  on_handle_begin();
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = (void*)phy->buf;
  iov.iov_len = get_buf_length();
  iov_iter_init(&(msg.msg_iter), WRITE | ITER_IOVEC, &iov, 1, iov.iov_len);
  res = sock_sendmsg(phy->tpmd_sock, &msg);
  if (res < 0) {
    error("sock_sendmsg() failed: %d\n", res);
    goto on_error;
  }
  set_fs(oldmm);
  on_handle_send_complete();
  oldmm = get_fs();
  set_fs(KERNEL_DS);
  /* receive response from tpmd */
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = (void*)phy->buf;
  iov.iov_len = TPM_CMD_BUF_SIZE;
  iov_iter_init(&(msg.msg_iter), READ | ITER_IOVEC, &iov, 1, iov.iov_len);
  res = sock_recvmsg(phy->tpmd_sock, &msg,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
                     TPM_CMD_BUF_SIZE,
#endif
                     0);
  set_fs(oldmm);
  if (res < 0) {
    error("sock_recvmsg() failed: %d\n", res);
    goto on_error;
  }
  phy->tail_index = res;
  on_handle_recv_complete();
  return 0;
on_error:
  set_fs(oldmm);
  on_handle_error();
  return res;
}
/*
static int parse_command_and_excute(u32 addr, u16 len, u8 *buffer, bool is_read) {
  if (!phy) return -1;
  //dev_dbg(phy->dev, "get command:addr:(%x),len:%d,isread:%d", addr, len, is_read);
  if (len == 1){
    // read/write 8bit
    if(is_read) {
      if (addr == TPM_ACCESS(phy->priv.locality)){ // get access property;
        *buffer = get_access_prop();
 //       dev_dbg(phy->dev, "return access status:(%x)", *buffer);
        return 0;
      }
      if (addr == TPM_STS(phy->priv.locality)) { // get status;
        *buffer = get_status_prop();
  //      dev_dbg(phy->dev, "return status:(%x)", *buffer);
        return 0;
      }
      if (addr == TPM_RID(phy->priv.locality)) { // get release id;
        *buffer = get_rid();
  //      dev_dbg(phy->dev, "return rid:(%x)", *buffer);
        return 0;
      }

    } else {
      if (addr == TPM_STS(phy->priv.locality)) {
        if (*buffer == TPM_STS_COMMAND_READY){ // reset system;
          reset_phy();
          return 0;
        }
        if (*buffer == TPM_STS_GO){ // excute the command stored in buf
          return tpmd_handle_command();
        }
      }
      if (addr == TPM_ACCESS(phy->priv.locality)){
        if (*buffer == TPM_ACCESS_ACTIVE_LOCALITY) {
            reset_phy();
            inactive_locality();
            return 0;
        }
      }

    }
  }
  if (addr == TPM_DATA_FIFO(phy->priv.locality)) {
    if (is_read) {
      return fetch_data(buffer, len);
    }else {
      return push_data(buffer, len);
    }
  } else {
    if (is_read) {
      memset(buffer,0 ,len);
      return 0;
    }else {
      return 0;
    }
  }
}
*/
static int read_and_excute(u32 addr, u16 len, u8 *buffer) { 
  if (!phy) return -1;
    //dev_dbg(phy->dev, "get command:addr:(%x),len:%d,isread:%d", addr, len, is_read);
  if (len == 1){
    if (addr == TPM_ACCESS(phy->priv.locality)){ // get access property;
      *buffer = get_access_prop();
 //   dev_dbg(phy->dev, "return access status:(%x)", *buffer);
      return 0;
    }
    if (addr == TPM_STS(phy->priv.locality)) { // get status;
      *buffer = get_status_prop();
  //  dev_dbg(phy->dev, "return status:(%x)", *buffer);
      return 0;
    }
      if (addr == TPM_RID(phy->priv.locality)) { // get release id;
      *buffer = get_rid();
  //  dev_dbg(phy->dev, "return rid:(%x)", *buffer);
      return 0;
    }
  }
  if (addr == TPM_DATA_FIFO(phy->priv.locality)) {
      return fetch_data(buffer, len);
  } else {
      memset(buffer,0 ,len);
      return 0;
  }
}

static int write_and_excute(u32 addr, u16 len, const u8 *buffer) {
  if (!phy) return -1;
    //dev_dbg(phy->dev, "get command:addr:(%x),len:%d,isread:%d", addr, len, is_read);
  if (len == 1){
    if (addr == TPM_STS(phy->priv.locality)) {
      if (*buffer == TPM_STS_COMMAND_READY){ // reset system;
          reset_phy();
          return 0;
      }
      if (*buffer == TPM_STS_GO){ // excute the command stored in buf
        if (is_request_cap()) {
			u32 req = get_req_cmd();
			if (can_handle_prop_req(req))
				return handle_prop_req(req);
		}
        return tpmd_handle_command();
      }
    }
    if (addr == TPM_ACCESS(phy->priv.locality)){
      if (*buffer == TPM_ACCESS_ACTIVE_LOCALITY) {
        reset_phy();
        inactive_locality();
        return 0;
      }
    }
  }
  if (addr == TPM_DATA_FIFO(phy->priv.locality)) {
      return push_data(buffer, len);
  } else {
      return 0;
  }
}

static int tpmd_read_bytes(struct tpm_tis_data *data, u32 addr,
			       u16 len, u8 *result) {
  int res=0;
  mutex_lock(&phy->emulator_mutex);
  res = read_and_excute(addr, len, result);
  if (res < 0) {
    dev_err(phy->dev, "tpmd_read_bytes() failed: %d\n", res);
  } else {
    res = 0;
  }
  mutex_unlock(&phy->emulator_mutex);
  return res;
}

static int tpmd_write_bytes(struct tpm_tis_data *data, u32 addr,
				u16 len, const u8 *value)
{
  int res;
  mutex_lock(&phy->emulator_mutex);
  res = write_and_excute(addr, len, value);
  if (res < 0) {
    dev_err(phy->dev, "tpmd_write_bytes() failed: %d, len: %d, value: %02x\n", res, len, *value);
  } else {
    res = 0;
  }
  mutex_unlock(&phy->emulator_mutex);
  return res;
}

static int tpmd_read16(struct tpm_tis_data *data, u32 addr, u16 *result)
{
	int rc;
	__le16 le_val;

	rc = data->phy_ops->read_bytes(data, addr, sizeof(u16), (u8 *)&le_val);
	if (!rc)
		*result = le16_to_cpu(le_val);
	return rc;
}

static int tpmd_read32(struct tpm_tis_data *data, u32 addr, u32 *result)
{
	int rc;
  __le32 le_val;
  if (!phy) return -1;
  if (addr == TPM_STS(phy->priv.locality)) { // get burst count;
    *result = get_bust_count();
    return rc;
  }
  if (addr == TPM_INT_STATUS(phy->priv.locality)) { // no irq;
    *result = 0;
    return -1;
  }
  if (addr == TPM_INT_ENABLE(phy->priv.locality)) { //bypass the int setting;
    *result = 0;
    return 0;
  }
  if (addr == TPM_INTF_CAPS(phy->priv.locality)) { // get tpm capacity ;
    *result = get_caps();
    return 0;
  }
  if (addr == TPM_DID_VID(phy->priv.locality)) { //get tpm vendor id;
    *result = get_vid();
    return 0;
  }

	rc = data->phy_ops->read_bytes(data, addr, sizeof(u32), (u8 *)&le_val);
	if (!rc)
		*result = le32_to_cpu(le_val);
	return rc;
}

static int tpmd_write32(struct tpm_tis_data *data, u32 addr, u32 value)
{
  __le32 le_val = cpu_to_le32(value);
  if (!phy) return -1;
	if (addr == TPM_INT_ENABLE(phy->priv.locality)){ // bypass int settings;
    return 0;
  }

	return data->phy_ops->write_bytes(data, addr, sizeof(u32),
					   (const u8 *)&le_val);
}

static const struct tpm_tis_phy_ops tpm_emulator_phy_ops = {
	.read_bytes = tpmd_read_bytes,
	.write_bytes = tpmd_write_bytes,
	.read16 = tpmd_read16,
	.read32 = tpmd_read32,
	.write32 = tpmd_write32,
	.max_xfer_size = TPM_CMD_BUF_SIZE,
};

static int register_to_tpm_tis(void){
  int ret;
  if (!phy) return -1;
  dev_info(phy->dev, "registering tpm_tis interface.\n");
  reset_phy();
  ret = tpm_tis_core_init(phy->dev, &phy->priv, -1, &tpm_emulator_phy_ops, NULL);
  if (ret < 0) {
    dev_err(phy->dev, "tpm_tis init error:%d", ret);
    goto on_error;
  }
  dev_info(phy->dev, "tpm_tis initialized.\n");
  return 0;
on_error:
  _status = 0;
  return ret;
}

static int tpm_open(struct inode *inode, struct file *file) {return 0;}
static int tpm_release(struct inode *inode, struct file *file) {return 0;}
static ssize_t tpm_read(struct file *file, char *buf, size_t count, loff_t *ppos) {
  if (_status != 0){
    strcpy(buf, "OK");
    return 3;
  }else {
    strcpy(buf, "NO");
    return 3;
  }
}

static ssize_t tpm_write(struct file *file, const char *buf, size_t count, loff_t *ppos) {
  int ret;
  dev_info(phy->dev, "get sig: %s", buf);
  if (strncmp(buf, TPM_READY_SIG, strlen(TPM_READY_SIG)) == 0) {
    dev_info(phy->dev, "begin open socked.");
    ret = tpmd_connect(tpmd_socket_name);
    if (ret != 0) {
      dev_err(phy->dev, "socket open error:%d", ret);
      return count;
    }
    register_to_tpm_tis();
  }
  return count;
};
static long tpm_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {return -1;}

struct file_operations fops = {
  .owner   = THIS_MODULE,
  .open    = tpm_open,
  .release = tpm_release,
  .read    = tpm_read,
  .write   = tpm_write,
  .compat_ioctl   = tpm_ioctl,
};

static struct miscdevice tpm_dev = {
  .minor      = TPM_DEVICE_MINOR,
  .name       = TPM_DEVICE_ID,
  .fops       = &fops,
};

int __init init_tpm_module(void)
{
  int ret = 0;
  int res = misc_register(&tpm_dev);
  info("begin init");
  if (res != 0) {
    error("misc_register() failed for minor %d\n", TPM_DEVICE_MINOR);
    goto on_error;
  }
  info("create phy");
  phy = kzalloc(sizeof(*phy), GFP_KERNEL);
  if (phy == NULL){
    ret = -ENOMEM;
    error("Got Error:%d", ret);
    goto on_error;
  }
  phy->dev = tpm_dev.this_device;
  mutex_init(&phy->emulator_mutex);
  return 0;
on_error:
  if (phy) kfree(phy);
  phy = NULL;
  misc_deregister(&tpm_dev);
  return ret;
}

void __exit cleanup_tpm_module(void)
{
  tpmd_disconnect();
  if(phy) kfree(phy);
  misc_deregister(&tpm_dev);
}

module_init(init_tpm_module);
module_exit(cleanup_tpm_module);
