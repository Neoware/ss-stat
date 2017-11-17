#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include "fr_scumbag_test_jni_App.h"

int send_netlink_msg(int fd, int family);
int recv_msg(int fd);

enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING
};

static const char* tcp_states_map[]= {
  [TCP_ESTABLISHED] = "ESTABLISHED",
  [TCP_SYN_SENT] = "SYN-SENT",
  [TCP_SYN_RECV] = "SYN-RECV",
  [TCP_FIN_WAIT1] = "FIN-WAIT-1",
  [TCP_FIN_WAIT2] = "FIN-WAIT-2",
  [TCP_TIME_WAIT] = "TIME-WAIT",
  [TCP_CLOSE] = "CLOSE",
  [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
  [TCP_LAST_ACK] = "LAST-ACK",
  [TCP_LISTEN] = "LISTEN",
  [TCP_CLOSING] = "CLOSING"
};

#define TCPF_ALL 0xFFF
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

JNIEXPORT jobjectArray JNICALL Java_fr_scumbag_test_jni_App_get_1tcp_1data
  (JNIEnv *env, jobject obj) {
  int fd;

  (void)env;
  (void)obj;
  if((fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1) {
    perror("socket: ");
  }

  send_netlink_msg(fd, AF_INET);
  recv_msg(fd);
  send_netlink_msg(fd, AF_INET6);
  recv_msg(fd);
  close(fd);
}

int send_netlink_msg(int fd, int family) {
  struct msghdr msg;
  struct nlmsghdr nlh;
  struct inet_diag_req_v2 conn_req;
  struct sockaddr_nl sa;
  struct iovec iov[2];

  memset(&msg, 0, sizeof(msg));
  memset(&sa, 0, sizeof(sa));
  memset(&nlh, 0, sizeof(nlh));
  memset(&conn_req, 0, sizeof(conn_req));

  sa.nl_family = AF_NETLINK;
  
  conn_req.sdiag_family = family;
  conn_req.sdiag_protocol = IPPROTO_TCP;
  conn_req.idiag_states = TCPF_ALL;
  conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
  conn_req.idiag_ext |= (1<<(INET_DIAG_VEGASINFO-1));
  conn_req.idiag_ext |= (1<<(INET_DIAG_CONG-1));
  
  nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
  nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

  iov[0].iov_base = (void*) &nlh;
  iov[0].iov_len = sizeof(nlh);
  iov[1].iov_base = (void*) &conn_req;
  iov[1].iov_len = sizeof(conn_req);

  msg.msg_name = (void*) &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  sendmsg(fd, &msg, 0);
  
  return 0;
}

void parse_diag_msg(struct inet_diag_msg *diag_msg) {
  char local_addr_buf[INET6_ADDRSTRLEN];
  char remote_addr_buf[INET6_ADDRSTRLEN];

  memset(local_addr_buf, 0, sizeof(local_addr_buf));
  memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

  if(diag_msg->idiag_family == AF_INET) {
    inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src),
	      local_addr_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst),
	      remote_addr_buf, INET_ADDRSTRLEN);
  } else if(diag_msg->idiag_family == AF_INET6) {
    inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
	      local_addr_buf, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
	      remote_addr_buf, INET6_ADDRSTRLEN);
  } else {
    fprintf(stderr, "Unknown family\n");
    return;
  }

  fprintf(stdout, "State %s -->  Src: %s:%d Dst: %s:%d\n",
	  tcp_states_map[diag_msg->idiag_state],
	  local_addr_buf, ntohs(diag_msg->id.idiag_sport),
	  remote_addr_buf, ntohs(diag_msg->id.idiag_dport)
	  );
  
  if(local_addr_buf[0] == 0 || remote_addr_buf[0] == 0) {
    fprintf(stderr, "Could not get required connection information\n");
    return;
  }
}

int recv_msg(int fd) {
  int response_len = 0;
  struct nlmsghdr *nlh;
  uint8_t response[SOCKET_BUFFER_SIZE];
  struct inet_diag_msg *diag_msg;

  while(42) {
    response_len = recv(fd, response, sizeof(response), 0);
    nlh = (struct nlmsghdr*) response;

    while(NLMSG_OK(nlh, response_len)) {
      if(nlh->nlmsg_type == NLMSG_DONE) {
	printf("DONE\n");
	return 0;
      }

      if(nlh->nlmsg_type == NLMSG_ERROR) {
	fprintf(stderr, "Error in netlink message\n");
	return -1;
      }
      diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
      parse_diag_msg(diag_msg);
      nlh = NLMSG_NEXT(nlh, response_len);      
    }
  }
  return 0;
}
