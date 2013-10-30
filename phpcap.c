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

ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_create, 0, 0, 1)
	ZEND_ARG_INFO(0, iface)
	ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_dispatch, 0, 0, 2)
	ZEND_ARG_INFO(0, rsrc)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, num_packets)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_close, 0, 0, 1)
	ZEND_ARG_INFO(0, rsrc)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_set_direction, 0, 0, 2)
	ZEND_ARG_INFO(0, rsrc)
	ZEND_ARG_INFO(0, direction)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_stats, 0, 0, 1)
	ZEND_ARG_INFO(0, rsrc)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_dispatch_break, 0, 0, 1)
	ZEND_ARG_INFO(0, rsrc)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_phpcap_filter, 0, 0, 2)
	ZEND_ARG_INFO(0, rsrc)
	ZEND_ARG_INFO(0, filter_string)
ZEND_END_ARG_INFO()

static void pcap_dispatch_cb(u_char *cargs, const struct pcap_pkthdr *header, const u_char *packet)
{
	zend_fcall_info *fci        = NULL;
	zend_fcall_info_cache *fcic = NULL;
	zval *param_packet, *param_cap = NULL;

	ether_header *ethernet = NULL;
	ip_header *ip          = NULL;
	char out[40];

	memcpy(&fci, cargs, sizeof(fci));
	memcpy(&fcic, cargs + sizeof(fci), sizeof(fcic));
	MAKE_STD_ZVAL(param_packet);MAKE_STD_ZVAL(param_cap);
	ZVAL_STRINGL(param_packet, packet, header->len, 1);
	array_init(param_cap);

	ethernet = (ether_header *)packet;
	ip       = (ip_header *)packet+sizeof(ether_header);

	char type[7];
	snprintf(type, sizeof(type), "0x%x", ntohs(ethernet->ether_type));
	add_assoc_string(param_cap, "ether_type", type, 1);
	add_assoc_string(param_cap, "source_host", ether_ntoa((const struct ether_addr *)ethernet->ether_shost), 1);
	add_assoc_string(param_cap, "destination_host", ether_ntoa((const struct ether_addr *)ethernet->ether_dhost), 1);

	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
		add_assoc_string(param_cap, "destination_ip", (char*)inet_ntop(AF_INET, &ip->ip_dst, out, sizeof(out)), 1);
		add_assoc_string(param_cap, "source_ip", (char*)inet_ntop(AF_INET, &ip->ip_src, out, sizeof(out)), 1);
	}

	zval ***params = emalloc(2 * sizeof(zval **));
	params[0] = &param_packet;
	params[1] = &param_cap;

	fci->params = params;
	fci->param_count = 2;

	zend_call_function(fci, fcic);

	if(fci->retval_ptr_ptr) {
		zval_ptr_dtor(fci->retval_ptr_ptr);
	}
	zval_ptr_dtor(&param_packet);
	zval_ptr_dtor(&param_cap);
	efree(params);
}

static void phpcap_rsrc_dtor(zend_rsrc_list_entry *rsrc)
{
	phpcap_t *phpcap = (phpcap_t *)rsrc->ptr;

	if(phpcap) {
		pcap_close(phpcap->pcap_dev);
		efree(phpcap);
	}
}

PHP_FUNCTION(phpcap_close)
{
	zval *rsrc       = NULL;
	phpcap_t *phpcap = NULL;

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "r", &rsrc) == FAILURE) {
		return;
	}

	PHPCAP_FETCH_RSRC(rsrc);

	zend_list_delete(Z_LVAL_P(rsrc));
}

PHP_FUNCTION(phpcap_create)
{
	char *iface = NULL;
	int iface_len;
	pcap_t *pcap_dev = NULL;
	phpcap_t *phpcap = NULL;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	long options = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &iface, &iface_len, &options) ==  FAILURE) {
		return;
	}

	pcap_dev = pcap_create(iface, pcap_errbuf);

	if (!pcap_dev) {
		php_error(E_WARNING, "%.*s", PCAP_ERRBUF_SIZE, pcap_errbuf);
		return;
	}

	if(options & PHPCAP_DEV_RFMON) {
		/* use pcap_can_set_rfmon(); to probe ? */
		pcap_set_rfmon(pcap_dev, 1);
	}
	if(options & PHPCAP_DEV_PROMISC) {
		pcap_set_promisc(pcap_dev, 1);
	}

	pcap_set_timeout(pcap_dev, 1000);

	if (pcap_activate(pcap_dev)) {
		php_error(E_WARNING, "Could not activate the device");
		return;
	}

	if (pcap_set_datalink(pcap_dev, DLT_EN10MB)) {
		php_error(E_WARNING, "The device %s does not support Ethernet", iface);
		return;
	}

	phpcap = (phpcap_t *) emalloc(sizeof(phpcap_t));
	phpcap->pcap_dev  = pcap_dev;
	phpcap->options   = options;

	ZEND_REGISTER_RESOURCE(return_value, phpcap, le_phpcap);
}

PHP_FUNCTION(phpcap_dispatch)
{
	zend_fcall_info *fci        = (zend_fcall_info *)emalloc(sizeof(*fci));
	zend_fcall_info_cache *fcic = (zend_fcall_info_cache *)emalloc(sizeof(*fcic));
	zval *rsrc       = NULL;
	phpcap_t *phpcap = NULL;
	long num_packets = -1;
	zval *cbresult   = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rf|l", &rsrc, fci, fcic, &num_packets) == FAILURE) {
		efree(fci);
		efree(fcic);
		return;
	}

	PHPCAP_FETCH_RSRC(rsrc);

	u_char *args = emalloc(sizeof(zend_fcall_info *) + sizeof(zend_fcall_info_cache *));

	fci->retval_ptr_ptr = &cbresult;
	fci->size = sizeof(*fci);

	memcpy(args, &fci, sizeof(zend_fcall_info *));
	memcpy(args + sizeof(zend_fcall_info *), &fcic, sizeof(zend_fcall_info_cache *));

	RETVAL_BOOL(pcap_loop(phpcap->pcap_dev, num_packets, pcap_dispatch_cb, args));

	efree(args);
	efree(fci);
	efree(fcic);
}

PHP_FUNCTION(phpcap_stats)
{
	zval *rsrc       = NULL;
	phpcap_t *phpcap = NULL;
	struct pcap_stat stats;

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "r", &rsrc) == FAILURE) {
		return;
	}

	PHPCAP_FETCH_RSRC(rsrc);

	if(pcap_stats(phpcap->pcap_dev, &stats)) {
		php_error(E_WARNING, "No stats available");
		return;
	}

	array_init(return_value);
	add_assoc_long(return_value, "received_packets", stats.ps_recv);
	add_assoc_long(return_value, "dropped_packets", stats.ps_ifdrop + stats.ps_drop);
}

PHP_FUNCTION(phpcap_dispatch_break)
{
	zval *rsrc       = NULL;
	phpcap_t *phpcap = NULL;

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "r", &rsrc) == FAILURE) {
		return;
	}

	PHPCAP_FETCH_RSRC(rsrc);

	pcap_breakloop(phpcap->pcap_dev);
}

PHP_FUNCTION(phpcap_set_direction)
{
	zval *rsrc       = NULL;
	phpcap_t *phpcap = NULL;
	long direction;

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "rl", &rsrc, &direction) == FAILURE) {
		return;
	}

	PHPCAP_FETCH_RSRC(rsrc);

	if(!pcap_setdirection(phpcap->pcap_dev, direction)) {
		php_error(E_WARNING, "Could not change device direction, maybe your OS or device does not support it");
		return;
	}
}

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

PHP_FUNCTION(phpcap_filter)
{
	zval *rsrc = NULL;
	char *filter_string;
	int filter_string_len;
	phpcap_t *phpcap = NULL;

	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	char errbuf[PCAP_ERRBUF_SIZE];

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &rsrc, &filter_string, &filter_string_len) == FAILURE) {
		return;
	}

	PHPCAP_FETCH_RSRC(rsrc);

	pcap_lookupnet(phpcap->pcap_dev,&netp,&maskp,errbuf);

	if(pcap_compile(phpcap->pcap_dev,&fp,filter_string,0,netp) == -1)
	{
		php_error(E_WARNING, "Could not set filter, check filter syntax");
		return;
	}

	if(pcap_setfilter(phpcap->pcap_dev,&fp) == -1)
	{
		php_error(E_WARNING, "Could not set filter, check filter syntax");
		return;
	}
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

	REGISTER_LONG_CONSTANT("PHPCAP_DEV_PROMISC", PHPCAP_DEV_PROMISC, CONST_PERSISTENT | CONST_CS);
	REGISTER_LONG_CONSTANT("PHPCAP_DEV_RFMON", PHPCAP_DEV_RFMON, CONST_PERSISTENT | CONST_CS);

	REGISTER_LONG_CONSTANT("PHPCAP_CAP_DIR_IN", PCAP_D_IN, CONST_PERSISTENT | CONST_CS);
	REGISTER_LONG_CONSTANT("PHPCAP_CAP_DIR_OUT", PCAP_D_OUT, CONST_PERSISTENT | CONST_CS);
	REGISTER_LONG_CONSTANT("PHPCAP_CAP_DIR_INOUT", PCAP_D_INOUT, CONST_PERSISTENT | CONST_CS);

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
	PHP_FE(phpcap_create,	arginfo_phpcap_create)
	PHP_FE(phpcap_findalldevs,	NULL)
	PHP_FE(phpcap_dispatch_break,	arginfo_phpcap_dispatch_break)
	PHP_FE(phpcap_dispatch,	arginfo_phpcap_dispatch)
	PHP_FE(phpcap_close,	arginfo_phpcap_close)
	PHP_FE(phpcap_stats,	arginfo_phpcap_stats)
	PHP_FE(phpcap_set_direction,	arginfo_phpcap_set_direction)
	PHP_FE(phpcap_filter,	arginfo_phpcap_filter)
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
