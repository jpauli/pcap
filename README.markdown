# Phpcap

The phpcap extension is a wrapper over [libpcap](http://www.tcpdump.org/pcap3_man.html) for PHP.

Usage example:

```php
/* Find possible devices and their associated addresses, if any */
var_dump(phpcap_findalldevs());
/*
array(4) {
  ["eth0"]=>
  array(3) {
    [0]=>
    string(7) "2.0.0.0"
    [1]=>
    string(14) "192.168.35.171"
    [2]=>
    string(7) "0.0.0.0"
  }
  ["wlan0"]=>
  array(2) {
    [0]=>
    string(7) "3.0.0.0"
    [1]=>
    string(7) "0.0.0.0"
  }
  ["any"]=>
  array(0) {
  }
  ["lo"]=>
  array(3) {
    [0]=>
    string(7) "1.0.0.0"
    [1]=>
    string(9) "127.0.0.1"
    [2]=>
    string(7) "0.0.0.0"
  }
}
*/

/* Create a resource with a device, you should need root access */
$r = phpcap_create('eth0');

/* Or create a resource in promiscuous mode */
$r = phpcap_create('eth0', PHPCAP_DEV_PROMISC);

/* If your device is wireless, you could use RFMON mode as well */
$r = phpcap_create('wlan0', PHPCAP_DEV_PROMISC | PHPCAP_DEV_RFMON);

/* You can filter for certain packets */
phpcap_filter($r, 'port 80');   // only capture packages on port 80

/* Use pcap_dispatch((resource) $pcap, (callback) $function, (int) $num_of_packet)
   to call a callback on each captured packet. */
phpcap_dispatch($r, function($rawpacket, $capture) { });

/* Use the last parameter to limit the number of packets to capture.
   The phpcap_dispatch() return TRUE on success, FALSE otherwise */
phpcap_dispatch($r, function($rawpacket, $capture) { }, 150);

/* The callback is passed the raw packet as first argument, you can play with raw data : */
phpcap_dispatch($r, function($rawpacket) { 
          var_dump( unpack('H12macdest/H12macsrc/H4ethtype/H24/a4ipsrc/a4ipdest',$rawpacket) 
                                         });

/* Better use the second parameter which provides parsed data : */
phpcap_dispatch($r, function($rawpacket, $capture) { var_dump($capture) });
/*
array(4) {
  ["ether_type"]=>
  string(5) "Ox806"
  ["source_host"]=>
  string(11) "0:9:f:9:0:5"
  ["destination_host"]=>
  string(16) "ff:ff:ff:ff:ff:ff"
}
*/

/* If the packet is of type IP (0x800), then more info are available : */
phpcap_dispatch($r, function($rawpacket, $capture) { var_dump($capture) });
/*
array(4) {
  ["ether_type"]=>
  string(5) "Ox800"
  ["source_host"]=>
  string(11) "0:9:f:9:0:5"
  ["destination_host"]=>
  string(16) "b4:99:ba:56:7e:0"
  ["destination_ip"]=>
  string(12) "109.13.10.68"
  ["source_ip"]=>
  string(13) "101.46.99.111"
}
*/

/* If you want to exit the callback, use phpcap_dispatch_break((resource) $pcap); */
phpcap_dispatch($r, function($packet, $cap) use ($r) { var_dump($cap); if(/*something*/) { phpcap_dispatch_break($r); }});

/* Time to get some stats : */
var_dump(phpcap_stats($r));
/*
array(2) {
  ["received_packets"]=>
  int(48)
  ["dropped_packets"]=>
  int(3)
}
*/

/* Finally, you may clean the resource with : */
phpcap_close($r);
```

Few notes :

* libpcap needed, actually only Linux is supported, may compile on BSD, PR are welcome
* Don't expect this to work on Windows platform, thanks for not asking for support :-)
* You may need to be root to capture device traffic
* You should refer to http://www.tcpdump.org/pcap3_man.html
* For an overview of filter-options refer to http://wiki.wireshark.org/CaptureFilters

Code is highly under development.
