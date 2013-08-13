/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Julien PAULI <jpauli@php.net>                                |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_PCAP_H
#define PHP_PCAP_H

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

extern zend_module_entry phpcap_module_entry;
#define phpext_pcap_ptr &phpcap_module_entry

#ifdef PHP_WIN32
#	define PHP_PCAP_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_PCAP_API __attribute__ ((visibility("default")))
#else
#	define PHP_PCAP_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define PHPCAP_RES_NAME "Pcap Resource"

typedef struct _phpcap_t {
	pcap_t *pcap_dev;
	short started;
} phpcap_t;

static void pcap_dispatch_cb(u_char *useless, const struct pcap_pkthdr * header, const u_char* packet);
static void phpcap_rsrc_dtor(zend_rsrc_list_entry *rsrc);

PHP_FUNCTION(phpcap_findalldevs);
PHP_FUNCTION(phpcap_create);
PHP_FUNCTION(phpcap_set_promisc);
PHP_FUNCTION(phpcap_set_rfmon);
PHP_FUNCTION(phpcap_can_set_rfmon);
PHP_FUNCTION(phpcap_list_datalinks);

/* 
  	Declare any global variables you may need between the BEGIN
	and END macros here:     

ZEND_BEGIN_MODULE_GLOBALS(pcap)
	long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(pcap)
*/

/* In every utility function you add that needs to use variables 
   in php_pcap_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as PCAP_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define PCAP_G(v) TSRMG(pcap_globals_id, zend_pcap_globals *, v)
#else
#define PCAP_G(v) (pcap_globals.v)
#endif

#endif	/* PHP_PCAP_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
