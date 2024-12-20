
//basement.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define TFTP_PORT 69
#define TFTP_BLOCK_SIZE 512
#define TFTP_DATA_PACKET_HEADER 4
#define MAX_BUFFER 65536

// 操作码
enum
{
    OP_RRQ = 1,  // 读请求
    OP_WRQ = 2,  // 写请求
    OP_DATA = 3, // 数据
    OP_ACK = 4,  // 确认
    OP_ERROR = 5 // 错误
};