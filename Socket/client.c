#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

// Input your port and server address
#define SERV_TCP_PORT 9924 
#define SERV_ADDR "127.0.0.1" 

main(){ 
   int x, y; 
   struct sockaddr_in  serv_addr; 
   char buf[100]; 

   printf("Hi, I am the client\n"); 

   bzero((char *) &serv_addr, sizeof(serv_addr)); 
   serv_addr.sin_family = PF_INET; 
   serv_addr.sin_addr.s_addr = inet_addr(SERV_ADDR); 
   serv_addr.sin_port = htons(SERV_TCP_PORT); 

   /* open a tcp socket*/ 
   if ( (x = socket(PF_INET, SOCK_STREAM,0)) < 0){ 
      perror("socket creation error\n"); 
      exit(1); 
   } 
   printf(" socket opened successfully. socket num is %d\n", x); 

   /* connect to  the server */ 
   if (connect(x, (struct sockaddr *) &serv_addr, sizeof(serv_addr))<0){ 
      perror("can't connect to the server\n"); 
      exit(1); 
   } 

    /* send msg to the server */ 
    printf("now i am connected to the erver. enter a string to send\n"); 
    scanf("%s", buf);
    write(x,buf,strlen(buf)); 

    // read from the server
    printf("now let's read from the server\n"); 
    y=read(x,buf,50); 
    buf[y]=0; 
    printf("what echoed from the server is %s\n",buf); 
    close(x);   // disconnect the connection
} 
