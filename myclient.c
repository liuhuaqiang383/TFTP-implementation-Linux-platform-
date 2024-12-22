//以下是TFTP客户端代码
#include "basement.h"

ssize_t recv_data(int sockfd, struct sockaddr_in* server_addr, unsigned short* blocknum, char* buffer);

void get_fuction(const char *server_ip, int server_port, const char *filename)
{
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned short blocknum = 1;
    ssize_t nBytes;
    FILE *file;

    // 创建UDP套接字
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid server IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 发送读请求
    send_request(sockfd, &server_addr, OP_RRQ, filename);

    // 打开文件用于写入
    file = fopen(filename, "ab");
    if (file == NULL)
    {
        perror("Unable to open the file");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 接收数据
    char buffer[TFTP_BLOCK_SIZE + TFTP_DATA_PACKET_HEADER];
    do
    {
        nBytes = recv_data(sockfd, &server_addr, &blocknum, buffer);
        if (nBytes < 0)
        {
            perror("Data reception failed");
            fclose(file);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // 写入文件
        fwrite(buffer + TFTP_DATA_PACKET_HEADER, 1, nBytes - TFTP_DATA_PACKET_HEADER, file);
        //printf("block received %d\n", blocknum);

        // 发送ACK
        send_ack(sockfd, &server_addr, blocknum);

        blocknum++;
    } while (nBytes == TFTP_BLOCK_SIZE + TFTP_DATA_PACKET_HEADER);

    printf("File reception completed.\n");

    fclose(file);
    close(sockfd);
}

void put_fuction(const char *server_ip, int server_port, const char *filename)
{
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned short blocknum = 0;
    ssize_t nBytes, read_bytes;
    FILE *file;
    char buffer[TFTP_BLOCK_SIZE + TFTP_DATA_PACKET_HEADER];
    struct sockaddr_in from_addr;
    socklen_t from_addr_len = sizeof(from_addr);

    // 创建UDP套接字
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid server IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 发送写请求
    send_request(sockfd, &server_addr, OP_WRQ, filename);

    // 打开文件以进行读取
    file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Unable to open the file");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 等待服务器的ACK响应
    while (1)
    {
        nBytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_addr_len);
        if (nBytes < 0)
        {
            perror("Failed to receive server response");
            fclose(file);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (buffer[1] == OP_ACK && buffer[2] == ((blocknum >> 8) & 0xFF) && buffer[3] == (blocknum & 0xFF))
        {
            // 更新服务器地址和端口
            server_addr.sin_addr = from_addr.sin_addr;
            server_addr.sin_port = from_addr.sin_port;
            break;
        }
        else
        {
            fprintf(stderr, "Unexpected ACK response received\n");
        }
    }

    // 将块编号重置为1
    blocknum = 1;

    // 循环发送数据块
    do
    {
        // 读取文件块
        char file_buffer[TFTP_BLOCK_SIZE];
        read_bytes = fread(file_buffer, 1, TFTP_BLOCK_SIZE, file);
        if (ferror(file))
        {
            perror("Failed to read the file");
            fclose(file);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // 发送文件块
        send_data(sockfd, &server_addr, blocknum, file_buffer, read_bytes);

        // 等待ACK
        nBytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_addr_len);
        if (nBytes < 0)
        {
            perror("Failed to receive ACK");
            fclose(file);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // 检查ACK块编号
        if (buffer[1] != OP_ACK || buffer[2] != ((blocknum >> 8) & 0xFF) || buffer[3] != (blocknum & 0xFF))
        {
            fprintf(stderr, "ACK received\n");
        }

        // 增加块编号
        blocknum++;
    } while (read_bytes == TFTP_BLOCK_SIZE);

    fclose(file);

    // 关闭套接字
    close(sockfd);

    printf("The file transfer completed successfully.\n");
}

void send_request(int sockfd, const struct sockaddr_in *server_addr, int opcode, const char *filename)
{
    char buffer[TFTP_BLOCK_SIZE + TFTP_DATA_PACKET_HEADER];
    int len = sprintf(buffer, "%c%c%s%c%s%c", 0, opcode, filename, 0, "octet", 0);

    if (sendto(sockfd, buffer, len, 0, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) != len)
    {
        perror("Request failed to send");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

void send_ack(int sockfd, const struct sockaddr_in *server_addr, unsigned short blocknum)
{

    char buffer[TFTP_DATA_PACKET_HEADER + 1]; //+1是给‘\0’留出空间
    sprintf(buffer, "%c%c%c%c", 0, OP_ACK, blocknum >> 8, blocknum & 0xFF);

    if (sendto(sockfd, buffer, TFTP_DATA_PACKET_HEADER, 0, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("ACK sending failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}


void send_data(int sockfd, const struct sockaddr_in *server_addr, unsigned short blocknum, const char *buffer, int buflen)
{
    char packet[TFTP_BLOCK_SIZE + TFTP_DATA_PACKET_HEADER];
    int packetlen = TFTP_DATA_PACKET_HEADER + buflen;
    // 创建数据包头部
    packet[0] = 0;
    packet[1] = OP_DATA;
    packet[2] = (blocknum >> 8) & 0xFF;
    packet[3] = blocknum & 0xFF;
    // 拷贝数据到数据包
    memcpy(packet + TFTP_DATA_PACKET_HEADER, buffer, buflen);

    // 发送数据包
    if (sendto(sockfd, packet, packetlen, 0, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) != packetlen)
    {
        perror("Data sending failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}


int main(int argc, char* argv[]) {
    
    int server_port = TFTP_PORT;
    
    if (argc != 4) {
        printf("The client usage：%s <server IP> <get/put> <filename>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* server_ip = argv[1];
    const char* command = argv[2];
    const char* filename = argv[3];

    if (strcmp(command, "get") == 0) {
        tftp_get(server_ip, server_port, filename);
    } else if (strcmp(command, "put") == 0) {
        tftp_put(server_ip, server_port, filename);
    } else {
        printf("Unsupported command：%s\n", command);
        exit(EXIT_FAILURE);
    }

    return 0;
}


ssize_t recv_data(int sockfd, struct sockaddr_in *server_addr, unsigned short *blocknum, char *buffer){
    
    socklen_t addrlen = sizeof(struct sockaddr_in);
    ssize_t nBytes = recvfrom(sockfd, buffer, TFTP_BLOCK_SIZE + TFTP_DATA_PACKET_HEADER, 0, (struct sockaddr *)server_addr, &addrlen);

    if (nBytes < TFTP_DATA_PACKET_HEADER)
    {
        return -1; // 接收到的数据小于最小数据包大小
    }

    // 解析块号
    if (buffer[1] == OP_DATA)
    {
        *blocknum = (unsigned char)buffer[2] << 8 | (unsigned char)buffer[3];
    }
    else if (buffer[1] == OP_ACK)
    {
        *blocknum = (unsigned char)buffer[2] << 8 | (unsigned char)buffer[3];
        return 0; // 只是ACK，没有数据
    }
    else
    {
        return -1; // 无效的操作码
    }
    return nBytes;
}


