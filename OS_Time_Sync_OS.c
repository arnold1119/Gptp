//Added addtional includes
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/bpf.h>
#include <net/ethertypes.h>
#include <net/if_ether.h>

#include <stddef.h>
#include "OS_Time_Sync.h"
#include "SMManagement.h"
#include "Connector_Net_Cfg.h"
#include "Connector_Api.h"
#include "OS_Time_Sync_PTP.h"
#include "AbsSoAd_PBCfg.h"
#include "AbsSoAd.h"

#define OS_TS_START_SEC_CODE
#include "OS_TS_MemMap.h"

extern Connector_SocketConfigType *  HostNetworkCfg;
/* Global for Raw Socket used */
#if (ABSSOAD_USE_RAW_SOCKET_POSIX ==  STD_ON)
static int OSTS_bpf                  = -1;
static char OSTS_bpf_dev[]           = "/dev/bpf0";  /* Need to adjust with real HW */
static uint32 AbsSoAd_MaxBPFBufferlength;
#endif

#if (ABSSOAD_USE_RAW_SOCKET_POSIX ==  STD_ON)
Std_ReturnType OSTS_Open_BPFDevice(Connector_SocketConfigType const * HostNetworkCfg) 
{
  Std_ReturnType RetVal = E_NOT_OK;
  struct ifreq bpf_bound_if;                 // interface name (ravb)

  /* size of buffer of all raw ethernet frames + bpf packet header */
  uint32 AS_MaxBPFBufferlength = MW_DEX_SUM_OF_FRAME_LEN; 

  uint32 bpf_rx_buf_len_readback = 0u;
  
  log_debug("OSTS BPF RX Buffer from config: %d",AS_MaxBPFBufferlength);
  
  int bpf_immediate_mode = 1;

  // Copy own interface name that will be used by the bpf to send/receive
  strncpy(bpf_bound_if.ifr_name, HostNetworkCfg->Interface, 8);

  /* BPF setup for raw Eth frame transmission */
  int bpf = open(OSTS_bpf_dev, O_RDWR); // open file descriptor for device
  if (bpf < 0) {
      log_error("AbsSoAd::Failed opening /dev/bpf0");
      close(bpf);
      return E_NOT_OK;
  } else {/* continue */};
  
  if (ioctl(bpf, BIOCIMMEDIATE, &bpf_immediate_mode) < 0) 
  { 
      /* return immediately upon packet read */
      log_error("AbsSoAd::Can't set IMMEDIATE mode on bpf device");
      close(bpf);
      return E_NOT_OK;
  } else {/* continue */};
  
  /* set BPF buffer length */
  if (ioctl(bpf, BIOCSBLEN, (caddr_t)&AS_MaxBPFBufferlength) < 0) {
      log_error("AbsSoAd::Can't set buffer length of bpf device");
      close(bpf);
      return E_NOT_OK;
  } else {/* continue */}; 
  
  /* read back buffer length */
  if (ioctl(bpf, BIOCGBLEN, &bpf_rx_buf_len_readback) < 0) { 
      log_error("AbsSoAd::Can't get buffer length of bpf device");
      close(bpf);
      return E_NOT_OK;
  } else {/* continue */}; 
  
  /* check readback value of what was set */
  if (bpf_rx_buf_len_readback != AS_MaxBPFBufferlength) { 
      log_error("AbsSoAd::bpf rx buffer length readback value is %d instead of %d",bpf_rx_buf_len_readback, AS_MaxBPFBufferlength);
      close(bpf);
      return E_NOT_OK;
  } else {/* continue */}; 
  
  /* bind bpf device to ravb interface */
  if (ioctl(bpf, BIOCSETIF, &bpf_bound_if) < 0) { // bind bpf device to ravb interface
      log_error("AbsSoAd::Can't bind bpf to interface");
      close(bpf);
      return E_NOT_OK;
  } else {/* continue */};  
  
  /* all packets processed on the interface */
  if (ioctl(bpf, BIOCPROMISC, NULL) < 0) { 
      log_error("AbsSoAd::Can't set device in promiscous mode");
      close(bpf);
      return E_NOT_OK;
    } else {/* continue */};  

  /* set bpf to non blocking mode  */
  if (fcntl(bpf, F_SETFL, O_NONBLOCK)) {  // set bpf to non blocking mode
      log_error("AbsSoAd::Can't set bpf in non-blocking mode");
      close(bpf);
      return E_NOT_OK;
    } else {/* continue */};  

  /* TODO: Save the BDF ID to host config */
  OSTS_bpf = bpf;

  return E_OK;
}
#endif

void OS_Time_Sync_Buffer_Init(OSTS_Sync_Ptp_Time_Buffer ** ptp_time_buffer, bool is_create)
{
    char OSTS_Name[50] = {0};
    sprintf(OSTS_Name, "%s", "OS_TS");

    uint32 oscs_mem_size = sizeof(OSTS_Sync_Ptp_Time_Buffer);
    *ptp_time_buffer = (OSTS_Sync_Ptp_Time_Buffer *) SM_Alloc(OSTS_Name, oscs_mem_size, SM_RW, is_create );
}

void OS_Time_Sync_PTP_Rcv(uint16 udp_socket_fd){
    struct sockaddr_in clientAddr;
    int rlen = 0;
    int sslen = sizeof(struct sockaddr_in);
    char buf[BUFF_LEN];

    rlen = recvfrom(udp_socket_fd, buf, BUFF_LEN, 0,(struct sockaddr *)&clientAddr,&sslen);
    if(rlen > 0){
#if OS_TIME_SYNC_MASTER == false
        OS_Time_Sync_PTP_Slave_Rcv_Handler(udp_socket_fd, clientAddr.sin_addr.s_addr, clientAddr.sin_port, buf, rlen);
#else        
        OS_Time_Sync_PTP_Master_Rcv_Handler(udp_socket_fd, clientAddr.sin_addr.s_addr, clientAddr.sin_port, buf, rlen);
#endif        
    }
}

#if (ABSSOAD_USE_RAW_SOCKET_POSIX == STD_ON)
uint16 OSTS_Cal_CSum (uint16 *buf, int nwords) 
{
    uint32 sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16) (~sum);
}
    
int OS_Time_Sync_Socket_Send(uint16 udp_socket_fd, uint8* buf, uint16 len
                             , uint32 dest_udp_addr, uint16 dest_udp_port){
    AS_RawMsgType   raw_buff;
    Std_ReturnType  ret               = E_NOT_OK;
    uint16          tx_len            = 0;     
    //const uint16 Rcv_VLID  = 0;
    memset(&raw_buff, 0, sizeof(raw_buff));  /* Init mem */

    /* Ethernet header */
    Sl_MemCpy(&raw_buff.source_mac_address, HostNetworkCfg->Mac_Addr, 6);          /* Source MAC */
    #if OS_TIME_SYNC_MASTER == true
    static const uint8 destmac[6]              = {0x01,0x00,0x5e,0x00,0x00,0x00};  /* Mother of all multicast MACs */
    #else
    static const uint8 destmac[6]              = MASTER_MAC_ADDRESS;               /* Dest MAC */
    #endif
    Sl_MemCpy(&raw_buff.dest_mac_address, destmac, 6);                             /* Dest MAC */
    //*((uint16 *)&raw_buff.dest_mac_address[4]) = htons(Rcv_VLID);                /* 只针对multicast */
    raw_buff.protocol                          = htons(0x800);                     /* Protocol type */

    /* Construct IP Header */
    static uint16 ipid       = 0;
    raw_buff.iph.ihl         = 5;
    raw_buff.iph.version     = 4;
    raw_buff.iph.tos         = 0;
    raw_buff.iph.tot_len     = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len); /* total len */
    raw_buff.iph.id          = htons(ipid++);                                             /* Id of this packet */
    raw_buff.iph.frag_off    = 0;
    raw_buff.iph.ttl         = 64;
    raw_buff.iph.protocol    = IPPROTO_UDP;
    raw_buff.iph.check       = 0;                                                         /* Set to 0 before calculating checksum */
    #if OS_TIME_SYNC_MASTER == true
    raw_buff.iph.saddr       = htonl((uint32)MASTER_IP_HEX);
    #else
    raw_buff.iph.saddr       = htonl((uint32)SLAVE_IP_HEX);    
    #endif
    raw_buff.iph.daddr       = dest_udp_addr;
    raw_buff.iph.check       = OSTS_Cal_CSum((uint16*)&raw_buff.iph, sizeof(struct iphdr)/2);         /* IP Header checksum */

    /* Construct UDP header */
    #if OS_TIME_SYNC_MASTER == true
    raw_buff.udph.uh_sport     = htons(MASTER_EVENT_PORT_HEX);                          /* Source port */ /* Fix with QNX QOS21 */
    #else
    raw_buff.udph.uh_sport     = htons(SLAVE_EVENT_PORT_HEX);
    #endif
    raw_buff.udph.uh_dport     = dest_udp_port;                                     /* Dest port */ /* Fix with QNX QOS21 */
    raw_buff.udph.uh_ulen      = htons(sizeof(struct udphdr) + len);                /* TCP header size */ /* Fix with QNX QOS21 */
    raw_buff.udph.uh_sum       = 0;                                                 /* leave checksum 0 now, filled later by pseudo header */ /* Fix with QNX QOS21 */

    /* Copy the payload */
    Sl_MemCpy (&raw_buff.data, buf, len);

    /* Write to BPD device with Socket_FD (BPD device ID here) */
    tx_len = write(OSTS_bpf, &raw_buff, offsetof(AS_RawMsgType,data)+len);
    if (tx_len < offsetof(AS_RawMsgType,data)+len) {
        log_debug ("AbsSoad: Could not send frame! len:%d, tx_len:%d VL:%d total:%u", len,tx_len);
        ret = E_NOT_OK;
    }
    log_debug ("RAW OS_Time_Sync_Socket_Send len:%d, tx_len:%d OSTS_bpf %d", len,tx_len, OSTS_bpf);
    return len;
} 
# else
int OS_Time_Sync_Socket_Send(uint16 udp_socket_fd, uint8* buf, uint16 len
                             , uint32 dest_udp_addr, uint16 dest_udp_port){
    struct sockaddr_in dest_addr; 
    int sslen = sizeof(struct sockaddr_in);                        
    dest_addr.sin_family           = AF_INET;
    dest_addr.sin_port             = dest_udp_port; 
    dest_addr.sin_addr.s_addr      = dest_udp_addr;   
    int xlen = sendto(udp_socket_fd, buf, len, 0, &dest_addr, sslen);
    if(xlen == -1){
        perror("OS TS Socket send failed");
    }
    return xlen;
}
#endif 


Std_ReturnType OS_Time_Sync_Socket_Init(uint32 udp_addr, uint16 udp_port, uint16* udp_socket_fd_ptr){
    struct sockaddr_in udp_addr_in;
    udp_addr_in.sin_family           = AF_INET;
    udp_addr_in.sin_port             = udp_port;
    udp_addr_in.sin_addr.s_addr      = udp_addr;

    int udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    // Bind the socketwo
    int opt = 1;
    int net_ret = -1;
    if (setsockopt(udp_socket_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))<0) {perror("setsockopt");exit(EXIT_FAILURE);}
    if (setsockopt(udp_socket_fd, SOL_SOCKET, SO_REUSEPORT, (char *)&opt, sizeof(opt))<0) {perror("setsockopt");exit(EXIT_FAILURE);}  
    if (bind(udp_socket_fd,(struct sockaddr_in*)&udp_addr_in,sizeof(struct sockaddr_in)) != 0)
    {
      log_debug("OS TS UDP Socket bind failed! Port: %d", ntohs(udp_addr_in.sin_port) );
      perror("Special ptp port need root permission");
      close(udp_socket_fd);
      exit(EXIT_FAILURE);
      return E_NOT_OK;
    } else { /* continue */ }
    /* Set non-block socket */
    net_ret = fcntl (udp_socket_fd, F_SETFL, O_NONBLOCK);
    int nonblock = TRUE;
    net_ret = ioctl (udp_socket_fd, FIONBIO, &nonblock);
    if(net_ret < 0)
    {
      log_debug("Could not set socket non-blocking");
      close(udp_socket_fd);
      return E_NOT_OK;
    } else { /* continue */}
    Sl_MemCpy(udp_socket_fd_ptr, &udp_socket_fd, sizeof(udp_socket_fd));
#if (ABSSOAD_USE_RAW_SOCKET_POSIX == STD_ON)    
    OSTS_Open_BPFDevice(HostNetworkCfg);
#endif 
    return E_OK; 
}

#if OS_TIME_SYNC_MASTER == true
Std_ReturnType OS_Time_Sync_Master_Socket_Init(uint16* udp_socket_fd_ptr){   
    OS_Time_Sync_Socket_Init(htonl((uint32)MASTER_IP_HEX), htons(MASTER_EVENT_PORT_HEX), udp_socket_fd_ptr);
}
#else
Std_ReturnType OS_Time_Sync_Slave_Socket_Init(uint16* udp_socket_fd_ptr){
    OS_Time_Sync_Socket_Init(htonl((uint32)SLAVE_IP_HEX), htons(SLAVE_EVENT_PORT_HEX), udp_socket_fd_ptr);
}
#endif
                 
#define OS_TS_STOP_SEC_CODE
#include "OS_TS_MemMap.h"