# Phpcap

The phpcap extension is a wrapper over [libpcap](http://www.tcpdump.org/pcap3_man.html) for PHP.

Example:

```php

<?php

$r = phpcap_create('eth0', PHPCAP_DEV_PROMISC);

/* Displaying Ethernet & IP headers */
phpcap_dispatch($r, function($packet) { var_dump( unpack('H12macdest/H12macsrc/H4ethtype/H24/a4ipsrc/a4ipdest',$packet) );}, 30 );

/* Ethernet and IP headers are available as second callback argument */
phpcap_dispatch($r, function($packet, $cap) { var_dump($cap); }, 30 );
/*
array(4) {
  ["source_host"]=>
  string(11) "0:9:f:9:0:5"
  ["destination_host"]=>
  string(16) "b4:99:ba:56:7e:0"
  ["destination_ip"]=>
  string(13) "36.16.138.110"
  ["source_ip"]=>
  string(13) "253.117.34.89"
}
*/

phpcap_close($r);
```

Few notes :

* libpcap needed, actually only Linux is supported, may compile on BSD, PR are welcome
* Don't expect this to work on Windows platform, thanks for not asking for support :-)
* You may need to be root to capture device traffic
* You should refer to http://www.tcpdump.org/pcap3_man.html

Code is highly under development.
