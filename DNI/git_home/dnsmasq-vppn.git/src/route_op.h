#ifndef _ROUTE_OP_H_
#define _ROUTE_OP_H_
#include <stdio.h>

int INET_setroute(char *name, char *target, char *netmask, char *gateway, char *device);
#endif
