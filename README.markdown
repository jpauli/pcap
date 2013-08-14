# Phpcap

The phpcap extension is a wrapper over [libpcap](http://www.tcpdump.org/pcap3_man.html) for PHP.

Example:

```php

<?php

$r = phpcap_create('eth0', PHPCAP_DEV_PROMISC);

/* Displaying Ethernet headers */
phpcap_dispatch($r, function($packet) { var_dump( unpack('H12dest/H12src/H4type',$packet) );}, 30 );

```

Few notes :

* libpcap needed, actually only Linux is supported, may compile on BSD, PR are welcome
* Don't expect this to work on Windows platform, thanks for not asking for support :-)
* You may need to be root to capture device traffic
* You should refer to http://www.tcpdump.org/pcap3_man.html

Code is highly under development.
