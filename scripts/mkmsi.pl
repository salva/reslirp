#!/usr/bin/perl

use strict;
use warnings;
use POSIX qw(strftime);
use XML::FromPerl qw(xml_from_perl);

my $release = shift @ARGV // "outside";
my ($version, $subversion) = (0, 0);
my $datetime = strftime "%y%m%d%H%M%S", localtime;

if (defined $release) {
    if ($release =~ /^v?(\d+)\.(\d+)/i) {
        $version = $1;
        $subversion = $2;
    }
    else {
        $release .= "-$datetime";
    }
}

sub clean_id {
    my $id = shift;
    $id =~ s/\W+/_/g;
    return $id;
}

sub get_win_path {
    my $posix = shift;
    open my $cp, '-|', 'cygpath', '-w', $posix or die "cygpath failed to resolve '$posix': $?";
    my $win_path = <$cp>;
    chomp $win_path;
    return $win_path
}

print "Building binary...\n";
system ("mkdir -p build && cd build && cmake .. && make") and die "Compilation failed";

my %deps;

open my $deps, '-|', 'ldd', 'build/reslirp.exe' or die "ldd failed: $?";
while (<$deps>) {
    chomp;
    s/^\s+|\s+$//g;
    if (my ($lib, $target) = /^\s*(.*?)\s+=>\s+(.*?)\s+\(0x[0-9a-f]+\)\s*$/) {
	if ($target =~ m|^/c/windows/|i) {
	    print "Ignoring system dependency $target\n\r";
	}
	else {
	    # print "Adding $win_path to the list of dependencies\n";
	    $deps{clean_id($lib)} = $target;
	}
    }
    else {
	print "WARNING: Unrecognized lib: $_"
    }
}

my %win_deps = map {$_ => get_win_path($deps{$_})} keys %deps;

my $wix_structure =
[ Wix => { xmlns => "http://wixtoolset.org/schemas/v4/wxs" },
  [ Package => { InstallerVersion => '500',
		 Compressed => "yes",
		 Name => "reSLIRP",
		 Manufacturer => "HappyRobotsLTD",
		 Version => "$version.$subversion.0.0",
		 UpgradeCode => sprintf("12345678-ABCD-%04d-%04d-%8s", $version, $subversion, $datetime),
		 Scope => 'perMachine' },
    [ MediaTemplate => { EmbedCab => "yes" } ],
    [ StandardDirectory => { Id => "ProgramFiles64Folder" },
      [ Directory => { Id => "INSTALLFOLDER", Name => "reSLIRP" },
	[ Component => { Id => "ProductComponent", Bitness => "always64" },
	  [ File => { Source => get_win_path("build/reslirp.exe"), Id => "MainExecutable", KeyPath=>"yes"} ],
	],
	[ Component => { Id => "Readme" },
	  [ File => { Id => "ReadmeFile", Source => "README.md", Name => "README.txt" } ]
	],
	[ Component => { Id => "Copyright" },
	  [ File => { Id => "CopyrightFile", Source => "COPYRIGHT", Name => "COPYRIGHT.txt" } ]
	],
	[ Component => { Id => "CopyrightSlirp" },
	  [ File => { Id => "CopyrightSlirpFile", Source => "COPYRIGHT.libslirp", Name => "COPYRIGHT_LIBSLIRP.txt" } ]
	],
        [ Component => { Id => "WinSshdSetup" },
	  [ File => { Id => "WinSshdSetupFile", Source => "win-sshd-setup.ps1", Name => "win-sshd-setup.ps1" } ]
	],
	map [ Component => { Id => $_, Bitness => 'always64' },
	      [ File => { Source => $win_deps{$_}, Id => $_, KeyPath => "yes" } ],
	], keys(%win_deps)
      ]
    ],
    [ Feature => {Id => "reSLIRPFeature"},
      [ ComponentRef => { Id => "ProductComponent" } ],
      [ ComponentRef => { Id => "Readme" } ],
      [ ComponentRef => { Id => "Copyright" } ],
      [ ComponentRef => { Id => "CopyrightSlirp" } ],
      [ ComponentRef => { Id => "WinSshdSetup" } ],
      map [ ComponentRef => { Id => $_ }], keys(%win_deps)
    ],
  ]
];

# Generate XML file
my $doc = xml_from_perl($wix_structure);

$doc->toFile("reslirp.wxs", 1);

print "WiX XML file 'reslirp.wxs' generated successfully!\n";

my $userdir = `cygpath -u \$USERPROFILE`;
chomp($userdir);

my $out_fn = "reSLIRP-${release}.msi";
system "$userdir/.dotnet/tools/wix build -bf -arch x64 reslirp.wxs -o $out_fn" and die "wix failed: $?";
print "$out_fn created";


