#
# spec file for "foo" - a canned fixture, not a real package.
#
Name:           foo
Version:        1.9
Release:        0
Summary:        A fixture package for the freshcrab tests
License:        Apache-2.0
Group:          Development/Tools
URL:            https://example.invalid/foo
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

%description
A fixture package for the freshcrab tests.

%prep
%autosetup

%build

%install

%files
%doc README.md
