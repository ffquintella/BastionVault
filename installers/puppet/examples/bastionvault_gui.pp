# Unattended install of the BastionVault desktop GUI on Windows, via
# Chocolatey, driven by Puppet.
#
# Nothing here is interactive: the `chocolatey` provider invokes
# `choco install -y`, and the package's own chocolateyInstall.ps1 passes the
# installer's silent flag (`/S` for the NSIS bundle, `/qn` for the .msi). No
# dialog, no language selector, no reboot prompt.
#
# Requires the puppetlabs/chocolatey module:
#   mod 'puppetlabs-chocolatey'
#
# See ../README.md for how the .nupkg is built and published.
class profile::bastionvault_gui (
  # Pin an exact version by default. Fleet installs should be reproducible:
  # 'latest' makes the installed version a function of when the agent last
  # ran, which is not something you want to debug during an incident.
  String[1] $version = '0.41.17',

  # Where the bastionvault-gui package comes from. Either a NuGet feed URL or
  # a UNC path / local directory holding the .nupkg — a file share is often
  # the pragmatic choice on a segregated network.
  String[1] $source = 'https://nuget.internal.example/chocolatey',

  # 'present' installs and holds $version; 'latest' tracks the feed; 'absent'
  # uninstalls through the package's chocolateyUninstall.ps1.
  Enum['present', 'latest', 'absent'] $ensure = 'present',
) {
  # Installs and configures Chocolatey itself if it is not there yet.
  include chocolatey

  # Register the feed as a named source so `choco` can also be used by hand on
  # the box, and so credentials (if any) live in one place.
  chocolateysource { 'bastionvault':
    ensure   => present,
    location => $source,
    priority => 10,
  }

  $_ensure = $ensure ? {
    'present' => $version,
    default   => $ensure,
  }

  package { 'bastionvault-gui':
    ensure   => $_ensure,
    provider => chocolatey,
    source   => $source,
    require  => Chocolateysource['bastionvault'],
  }
}
