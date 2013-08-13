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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_phpcap.h"

/* If you declare any globals in php_pcap.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(pcap)
*/

/* True global resources - no need for thread safety here */
static int le_phpcap;

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("pcap.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_pcap_globals, pcap_globals)
    STD_PHP_INI_ENTRY("pcap.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_pcap_globals, pcap_globals)
PHP_INI_END()
*/
/* }}} */

static void pcap_dispatch_cb(u_char *useless, const struct pcap_pkthdr *header, const u_char *packet)
{
	php_printf("got a packet ==> ");
	struct ether_header *cap_ether_header;

	cap_ether_header = (struct ether_header *)packet;
	php_printf("src addr: %s\n", ether_ntoa(cap_ether_header->ether_dhost));
}

static void phpcap_rsrc_dtor(zend_rsrc_list_entry *rsrc)
{
	phpcap_t *phpcap = (phpcap_t *)rsrc->ptr;

	if(phpcap) {
		pcap_close(phpcap->pcap_dev);
		efree(phpcap);
	}
}

PHP_FUNCTION(phpcap_create)
{
	char *iface = NULL;
	int iface_len;
	pcap_t *pcap_dev = NULL;
	phpcap_t *phpcap = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &iface, &iface_len) ==  FAILURE) {
		return;
	}

	pcap_dev = pcap_create(iface, pcap_errbuf);

	if (!pcap_dev) {
		php_error(E_WARNING, "%.*s", PCAP_ERRBUF_SIZE, pcap_errbuf);
		return;
	}

	phpcap = (phpcap_t *) emalloc(sizeof(phpcap_t));
	phpcap->pcap_dev  = pcap_dev;
	phpcap->started   = 0;

	ZEND_REGISTER_RESOURCE(return_value, phpcap, le_phpcap);
}

//PHP_FUNCTION(pcap_test)
//{
//	pcap_t *pcap_handle;
//	char pcap_errbuf[PCAP_ERRBUF_SIZE];
//
//	pcap_handle = pcap_open_live("eth0", BUFSIZ, 0, 1000, pcap_errbuf);
//	if (pcap_handle == NULL) {
//		php_error(E_WARNING, "Cannot open eth0 : %s", pcap_errbuf);
//		RETURN_NULL();
//	}
//
//	if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
//		php_error(E_WARNING, "Only Ethernet is supported");
//		RETURN_NULL();
//	}
//
//	//pcap_dispatch(pcap_handle, -1, pcap_dispatch_cb, pcap_errbuf);
//	pcap_loop(pcap_handle, -1, pcap_dispatch_cb, pcap_errbuf);
//
//}

PHP_FUNCTION(phpcap_findalldevs)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces = NULL, *iface = NULL;
	zval *details = NULL;

	if (pcap_findalldevs(&interfaces, errbuf) == -1) {
		php_error(E_WARNING, "%.*s", PCAP_ERRBUF_SIZE, errbuf);
		RETURN_NULL();
	}

	array_init(return_value);

	if(!interfaces) {
		php_error(E_NOTICE, "No interface found, perhaps you need to be root ?");
		return;
	}

	iface = interfaces;

	while(iface) {
		ALLOC_INIT_ZVAL(details);
		array_init(details);
		pcap_addr_t *address = iface->addresses;

		while(address) {
			add_next_index_string(details, inet_ntoa(((struct sockaddr_in *)address->addr)->sin_addr), 1);
			address = address->next;
		}
		add_assoc_zval_ex(return_value, iface->name, strlen(iface->name) + 1, details);
		iface = iface->next;
	}

	pcap_freealldevs(interfaces);
}
/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and 
   unfold functions in source code. See the corresponding marks just before 
   function definition, where the functions purpose is also documented. Please 
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_pcap_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_pcap_init_globals(zend_pcap_globals *pcap_globals)
{
	pcap_globals->global_value = 0;
	pcap_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(phpcap)
{
	/* If you have INI entries, uncomment these lines 
	REGISTER_INI_ENTRIES();
	*/

	le_phpcap = zend_register_list_destructors_ex(phpcap_rsrc_dtor, NULL, PHPCAP_RES_NAME, module_number);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(phpcap)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(phpcap)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(phpcap)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(phpcap)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "phpcap support", pcap_lib_version());
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ pcap_functions[]
 *
 * Every user visible function must have an entry in pcap_functions[].
 */
const zend_function_entry phpcap_functions[] = {
	PHP_FE(phpcap_create,	NULL)		/* For testing, remove later. */
	PHP_FE(phpcap_findalldevs,	NULL)
	PHP_FE_END	/* Must be the last line in pcap_functions[] */
};
/* }}} */

/* {{{ pcap_module_entry
 */
zend_module_entry phpcap_module_entry = {
	STANDARD_MODULE_HEADER,
	"phpcap",
	phpcap_functions,
	PHP_MINIT(phpcap),
	PHP_MSHUTDOWN(phpcap),
	PHP_RINIT(phpcap),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(phpcap),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(phpcap),
	"0.1", /* Replace with version number for your extension */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PHPCAP
ZEND_GET_MODULE(phpcap)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
