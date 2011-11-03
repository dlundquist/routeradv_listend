Summary: Userspace implementation of IPv6 default gateway autoconfiguration
Name: routeradv_listend
Version: 0.1
%define rel 1
Release: %{rel}%{?dist}
License: GPL
Group: System Environment/Kernel
Source: blueboxgroup-routeradv_listend-5b3108a.tar.gz
ExclusiveOS: Linux
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: iproute
URL: https://github.com/blueboxgroup/routeradv_listend

%description
This daemon listens for IPv6 router advertisments and dymanicly configures
the default IPv6 route. This behaviour is implemented in the kernel, but
disabled when IPv6 forwarding is enabled. This daemon allow a host which
forwarding enabled to use multiple default gateways to protect against
the case of a gateway failure like autoconfigured IPv6 hosts without
participating in an additional dynamic routing protocol. Applications
include NAT and VPN gateways and virtualization hosts.

%prep
%setup -n blueboxgroup-routeradv_listend-5b3108a

%build -n blueboxgroup-routeradv_listend-5b3108a
make

%install -n blueboxgroup-routeradv_listend-5b3108a
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
install -b -D -m 0755 ./routeradv_listend ${RPM_BUILD_ROOT}/sbin/routeradv_listend

%files
/sbin/routeradv_listend
