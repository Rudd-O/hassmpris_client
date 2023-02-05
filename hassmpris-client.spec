# See https://docs.fedoraproject.org/en-US/packaging-guidelines/Python/#_example_spec_file

%define debug_package %{nil}

%define dunder_name hassmpris_client
%define _name hassmpris-client

%define mybuildnumber %{?build_number}%{?!build_number:1}

Name:           python-%{_name}
Version:        0.0.20
Release:        %{mybuildnumber}%{?dist}
Summary:        Simple command-line client to control the MPRIS multimedia agent

License:        LGPLv2.1
URL:            https://github.com/Rudd-O/%{dunder_name}
Source:         %{url}/archive/v%{version}/%{dunder_name}-%{version}.tar.gz

Requires:       gtk4
Requires:       libnotify
BuildArch:      noarch
BuildRequires:  python3-devel, python-types-cryptography, openssl

%global _description %{expand:
This package contains a simple command-line utility that allows you to pair
and then control any computer with the MPRIS Linux desktop agen}

%description %_description

%package -n python3-%{_name}
Summary:        %{summary}

%description -n python3-%{_name} %_description

%prep
%autosetup -p1 -n %{dunder_name}-%{version}

%generate_buildrequires
%pyproject_buildrequires -t


%build
%pyproject_wheel


%install
%pyproject_install

%pyproject_save_files %{dunder_name}


%check
%tox


# Note that there is no %%files section for
# the unversioned python module, python-pello.

# For python3-pello, %%{pyproject_files} handles code files and %%license,
# but executables and documentation must be listed in the spec file:

%files -n python3-%{_name} -f %{pyproject_files}
%doc README.md
%{_bindir}/hassmpris-client


%changelog
* Thu Jun 16 2022 Manuel Amador <rudd-o@rudd-o.com> 0.1.0-1
- First RPM packaging release
