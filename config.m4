dnl $Id$
dnl config.m4 for extension pcap

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(phpcap, for phpcap support,
[  --with-phpcap             Include phpcap support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(pcap, whether to enable pcap support,
dnl Make sure that the comment is aligned:
dnl [  --enable-pcap           Enable pcap support])

if test "$PHP_PHPCAP" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-pcap -> check with-path
  SEARCH_PATH="/usr/local /usr"     # you might want to change this
  SEARCH_FOR="/include/pcap.h"  # you most likely want to change this
  if test -r $PHP_PHPCAP/$SEARCH_FOR; then # path given as parameter
     PCAP_DIR=$PHP_PHPCAP
   else # search default path list
     AC_MSG_CHECKING([for pcap files in default path])
     for i in $SEARCH_PATH ; do
       if test -r $i/$SEARCH_FOR; then
         PCAP_DIR=$i
         AC_MSG_RESULT(found in $i)
       fi
     done
   fi
  dnl
   if test -z "$PCAP_DIR"; then
     AC_MSG_RESULT([not found])
     AC_MSG_ERROR([Please reinstall the pcap distribution])
   fi

  dnl # --with-pcap -> add include path
   PHP_ADD_INCLUDE($PCAP_DIR/include)

  dnl # --with-pcap -> check for lib and symbol presence
   LIBNAME=pcap # you may want to change this
   LIBSYMBOL=pcap_lookupdev # you most likely want to change this 

   PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
   [
     PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PCAP_DIR/lib, PHPCAP_SHARED_LIBADD)
     AC_DEFINE(HAVE_PCAPLIB,1,[ ])
   ],[
     AC_MSG_ERROR([wrong pcap lib version or lib not found])
   ],[
     -L$PCAP_DIR/lib -lm
   ])
   PHP_SUBST(PHPCAP_SHARED_LIBADD)

  PHP_NEW_EXTENSION(phpcap, phpcap.c, $ext_shared)
fi
