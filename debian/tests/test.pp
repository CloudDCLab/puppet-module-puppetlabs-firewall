class profile::firewall {
  include ::firewall
  include ::fwrules
}
class fwrules {
  contain ::fwrules::ipv4
  contain ::fwrules::ipv6

  resources { 'firewall':
    purge => true,
  }

  resources { 'firewallchain':
    purge => true,
  }
}

class fwrules::ipv4 {
  Firewall {
    require => undef,
  }

  firewallchain { 'INPUT:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
  }

  # Default firewall rules
  firewall { "000 ${title} accept all icmp":
    proto  => 'icmp',
    action => 'accept',
  }
  ->
  firewall { "001 ${title} accept all to lo interface":
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }
  ->
  firewall { "003 ${title} accept related established rules":
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }
}

class fwrules::ipv6 {
  Firewall {
    require  => undef,
    provider => 'ip6tables'
  }

  firewallchain { 'INPUT:filter:IPv6':
    ensure => present,
    policy => drop,
    before => undef,
  }

  # Default firewall rules
  firewall { "000 ${title} accept all icmp":
    proto  => 'ipv6-icmp',
    action => 'accept',
  }
  ->
  firewall { "001 ${title} accept all to lo interface":
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }
  ->
  firewall { "003 ${title} accept related established rules":
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }
}

class profile::appserver {
  include ::firewall
  Firewall {
    require => Class['fwrules'],
  }

  firewall { "0100 ${title} Future-proof XMLRPC over UUCP over IPv6 appserver traffic":
    dport    => [540],
    proto    => tcp,
    action   => accept,
    source   => '2001:db8:de:caf::/64',
    provider => 'ip6tables',
  }

  firewall { "0101 ${name} legacy admin access":
    dport  => [80, 443],
    proto  => tcp,
    action => accept,
    source => '192.0.2.0/24',
  }

  firewall { "0101 ${name} admin access":
    dport    => [80, 443],
    proto    => tcp,
    action   => accept,
    provider => 'ip6tables',
    source   => '2001:db8:c0f:fee::/64',
  }

  # appserver things here
}

include profile::firewall
include profile::appserver
