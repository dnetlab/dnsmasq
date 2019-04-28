#include "dnsmasq.h"

#define RTACTION_ADD   1
#define RTACTION_DEL   2

#if defined (SIOCADDRTOLD) || defined (RTF_IRTT)        /* route */
#define HAVE_NEW_ADDRT 1
#endif
#ifdef RTF_IRTT                 /* route */
#define HAVE_RTF_IRTT 1
#endif
#ifdef RTF_REJECT               /* route */
#define HAVE_RTF_REJECT 1
#endif

#if HAVE_NEW_ADDRT
#  define mask_in_addr(x) (((struct sockaddr_in *)&((x).rt_genmask))->sin_addr.s_addr)
#  define full_mask(x) (x)
#else
#  define mask_in_addr(x) ((x).rt_genmask)
#  define full_mask(x) (((struct sockaddr_in *)&(x))->sin_addr.s_addr) 
#endif

#ifndef RTF_UP
/* Keep this in sync with /usr/src/linux/include/linux/route.h */
#define RTF_UP          0x0001          /* route usable                 */
#define RTF_GATEWAY     0x0002          /* destination is a gateway     */
#define RTF_HOST        0x0004          /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008          /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010          /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020          /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040          /* specific MTU for this route  */
#ifndef RTF_MSS
#define RTF_MSS         RTF_MTU         /* Compatibility :-(            */
#endif
#define RTF_WINDOW      0x0080          /* per route window clamping    */
#define RTF_IRTT        0x0100          /* Initial round trip time      */
#define RTF_REJECT      0x0200          /* Reject route                 */
#endif
////////////////////////route define end /////////////////////////

unsigned int tIpNetmask(unsigned int ip)
{
    int loop = 0;
    unsigned int netmask = 0xFFFFFFFF;
    unsigned int test = 0xFF;

    for (loop = 0; loop < 4; loop++) {
        test <<= loop*8;
        if ((test & ip) == 0) continue;
        else break;
    }

    return netmask << loop*8;
}

int INET_resolve(char *name, struct sockaddr *sa)
{
	struct sockaddr_in *s_in = (struct sockaddr_in *)sa;

	s_in->sin_family = AF_INET;
	s_in->sin_port = 0;

	/* Default is special, meaning 0.0.0.0. */
	if (strcmp(name, "default")==0) {
		s_in->sin_addr.s_addr = INADDR_ANY;
		return 1;
	}
	/* Look to see if it's a dotted quad. */
	if (inet_aton(name, &s_in->sin_addr)) {
		return 0;
	}
	/* guess not.. */
	return -1;
}

int INET_setroute(char *name, char *target, char *netmask, char *gateway, char *device)//char **args)
{
	struct rtentry rt;
	int  isnet;
	int skfd;
	struct sockaddr mask;
	int action = RTACTION_ADD;

	//dbg_printf(Mod_socket,"%sing static route destination [%s], mask[%s], gateway[%s] ... \n", (RTACTION_ADD==action)?"add":"delet", target, netmask, gateway);
	//my_syslog(LOG_INFO, _("insert [%s] route %s to gw %s"), name, target, gateway);

	/* Clean out the RTREQ structure. */
	memset((char *) &rt, 0, sizeof(struct rtentry));

	if ((isnet = INET_resolve(target, &rt.rt_dst)) < 0) {
		my_syslog(LOG_ERR,_("error target %s"), target);
		return -1;   /* XXX change to E_something */
	}

	rt.rt_flags = RTF_UP;

	// netmask
	if ((isnet = INET_resolve(netmask, &mask)) < 0) {
		//dbg_printf(Mod_socket,"can't resolve netmask %s", netmask);
		my_syslog(LOG_ERR,_("error mask %s"), netmask);
		return -1;
	}
	rt.rt_genmask = full_mask(mask);

	/* gateway*/
	if (NULL != gateway) {
		if ((isnet = INET_resolve(gateway, &rt.rt_gateway)) < 0) {
			my_syslog(LOG_ERR,_("error gateway %s"), gateway);
			return -1;
		}
		if (isnet) {
			my_syslog(LOG_ERR,_("%s: cannot use a NETWORK as gateway!"), gateway);
			return -1;
		}
		rt.rt_flags |= RTF_GATEWAY;
	}

	if (NULL != device) {
		rt.rt_dev = device;
	}

	/* sanity checks.. */
	if (mask_in_addr(rt)) {
		unsigned long mask = mask_in_addr(rt);
		mask = ~ntohl(mask);
		if ((rt.rt_flags & RTF_HOST) && mask != 0xffffffff) {
			my_syslog(LOG_ERR,_("netmask %.8x doesn't make sense with host route"), (unsigned int)mask);
			return -1;
		}
		if (mask & (mask + 1)) {
			my_syslog(LOG_ERR,_("bogus netmask %s"), netmask);
			return -1;
		}
		mask = ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr;
		if (mask & ~mask_in_addr(rt)) {
			my_syslog(LOG_ERR,_("netmask doesn't match route address"));
			return -1;
		}
	}
	/* Fill out netmask if still unset */
	if ((action == RTACTION_ADD) && rt.rt_flags & RTF_HOST)
		mask_in_addr(rt) = 0xffffffff;

	/* Create a socket to the INET kernel. */
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		my_syslog(LOG_ERR,_("socket: %s"), strerror(errno));
		return -1;
	}
	/* Tell the kernel to accept this route. */
	if (action == RTACTION_DEL) {
		if (ioctl(skfd, SIOCDELRT, &rt) < 0) {
			if (ENOENT != errno) {
				my_syslog(LOG_ERR,_("SIOCDELRT: del route %s mask %s gw %s error[%d] : %s"), 
					target, netmask, gateway, errno, strerror(errno));
			}
			close(skfd);
			return -1;
		}
	} else {
		if (ioctl(skfd, SIOCADDRT, &rt) < 0) {
			if (EEXIST != errno) {
				my_syslog(LOG_ERR,_("SIOCADDRT: add route %s mask %s gw %s error[%d] : %s"), 
					target, netmask, gateway, errno, strerror(errno));
			}
			close(skfd);
			return -1;
		} else {
			my_syslog(LOG_INFO, _("insert [%s] route %s to gw %s dev ~~~~%s"), name, target, gateway, device);
		}
	}

	/* Close the socket. */
	(void) close(skfd);
	return 0;
}

