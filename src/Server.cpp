#include "Server.h"
#include <cstring>
#include <iostream>
#include <unistd.h>
#ifdef __WIN32__
//needed if windows installation.
#include <winsock2.h>
#include <sys/types.h>
#else
//other unix installation
#include <sys/socket.h>
#include <netinet/in.h>
#endif

using namespace std;
//call WSA startup if windows installation
int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
