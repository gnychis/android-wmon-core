#!/usr/bin/perl
#
# make-doc.pl
# WSLUA's Reference Manual Generator
#
# (c) 2006, Luis E. Garcia Onatnon <luis@ontanon.org>
#
# $Id: make-wsluarm.pl 35731 2011-01-31 21:16:20Z jake $
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# (-: I don't even think writing this in Lua  :-)

use strict;
#use V2P;

sub deb {
#	warn $_[0];
}

sub gorolla {
# a gorilla stays to a chimp like gorolla stays to chomp
# but this one returns the shrugged string.
	my $s = shift;
	$s =~ s/^([\n]|\s)*//ms;
	$s =~ s/([\n]|\s)*$//ms;
	$s =~ s/\</&lt;/ms;
	$s =~ s/\>/&gt;/ms;
	$s;
}

my %module = ();
my %modules = ();
my $class;
my %classes;
my $function;
my @functions;

my $docbook_template = {
	module_header => "<section id='lua_module_%s'>\n",
	module_desc => "\t<title>%s</title>\n",
	module_footer => "</section>\n",
	class_header => "\t<section id='lua_class_%s'><title>%s</title>\n",
	class_desc => "\t\t<para>%s</para>\n",
	class_footer => "\t</section> <!-- class_footer: %s -->\n",
#	class_constructors_header => "\t\t<section id='lua_class_constructors_%s'>\n\t\t\t<title>%s Constructors</title>\n",
#	class_constructors_footer => "\t\t</section> <!-- class_constructors_footer -->\n",
#	class_methods_header => "\t\t<section id='lua_class_methods_%s'>\n\t\t\t<title>%s Methods</title>\n",
#	class_methods_footer => "\t\t</section> <!-- class_methods_footer: %s -->\n",
	class_attr_header => "\t\t<section id='lua_class_attrib_%s'>\n\t\t\t<title>%s</title>\n",
	class_attr_footer => "\t\t</section> <!-- class_attr_footer: %s -->\n",
	class_attr_descr => "\t\t\t<para>%s</para>\n",
	function_header => "\t\t\t<section id='lua_fn_%s'>\n\t\t\t\t<title>%s</title>\n",
	function_descr => "\t\t\t\t<para>%s</para>\n",
	function_footer => "\t\t\t</section> <!-- function_footer: %s -->\n",
	function_args_header => "\t\t\t\t\t<section><title>Arguments</title>\t\t\t\t<variablelist>\n",
	function_args_footer => "\t\t\t\t</variablelist></section>\n",
	function_arg_header => "\t\t\t\t<varlistentry><term>%s</term>\n",
	function_arg_descr => "\t\t\t\t\t<listitem><para>%s</para></listitem>\n",
	function_arg_footer => "\t\t\t\t</varlistentry> <!-- function_arg_footer: %s -->\n",
	function_argerror_header => "", #"\t\t\t\t\t<section><title>Errors</title>\n\t\t\t\t\t\t<itemizedlist>\n",
	function_argerror => "", #"\t\t\t\t\t\t\t<listitem><para>%s</para></listitem>\n",
	function_argerror_footer => "", #"\t\t\t\t\t\t</itemizedlist></section> <!-- function_argerror_footer: %s -->\n",
	function_returns_header => "\t\t\t\t<section><title>Returns</title>\n",
	function_returns_footer => "\t\t\t\t</section> <!-- function_returns_footer: %s -->\n",
	function_returns => "\t\t\t\t\t<para>%s</para>\n",
	function_errors_header => "\t\t\t\t<section><title>Errors</title><itemizedlist>\n",
	function_errors => "\t\t\t\t\t\t<listitem><para>%s</para></listitem>\n",
	function_errors_footer => "\t\t\t\t\t</itemizedlist></section> <!-- function_error_footer: %s -->\n",
	non_method_functions_header => "\t\t<section id='non_method_functions_%s'><title>Non Method Functions</title>\n",
	non_method_functions_footer => "\t\t</section> <!-- Non method -->\n",
};


my $template_ref = $docbook_template;
my $out_extension = "xml";

# It's said that only perl can parse perl... my editor isn't perl...
# if unencoded this causes my editor's autoindent to bail out so I encoded in octal
# XXX: support \" within ""
my $QUOTED_RE = "\042\050\133^\042\135*\051\042";

my $TRAILING_COMMENT_RE = '((\s*|[\n\r]*)/\*(.*?)\*/)?';

my @control =
(
# This will be scanned in order trying to match the re if it matches
# the body will be executed immediatelly after.
[ 'WSLUA_MODULE\s*([A-Z][a-zA-Z]+)([^\*]*)',
sub {
	$module{name} = $1;
	$module{descr} = $2
} ],

[ 'WSLUA_CLASS_DEFINE\050\s*([A-Z][a-zA-Z]+).*?\051;' . $TRAILING_COMMENT_RE,
sub {
	deb ">c=$1=$2=$3=$4=$5=$6=$7=\n";
	$class = {
		name => $1,
		descr=> gorolla($4),
		constructors => [],
		methods => [],
		attributes => []
	};
	$classes{$1} = $class;
} ],

[ 'WSLUA_FUNCTION\s+wslua_([a-z_]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">f=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $1,
		descr => gorolla($4),
		type => 'standalone'
	};
	push @functions, $function;
} ],

[ 'WSLUA_CONSTRUCTOR\s+([A-Za-z0-9]+)_([a-z0-9_]+).*?\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cc=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => "$1.$2",
		descr => gorolla($5),
		type => 'constructor'
	};
	push @{${$class}{constructors}}, $function;
} ],

[ '_WSLUA_CONSTRUCTOR_\s+([A-Za-z0-9]+)_([a-z0-9_]+)\s*(.*?)\052\057',
sub {
	deb ">cc=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => "$1.$2",
		descr => gorolla($3),
		type => 'constructor'
	};
	push @{${$class}{constructors}}, $function;
} ],

[ 'WSLUA_METHOD\s+([A-Za-z]+)_([a-z0-9_]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ":$2";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $name,
		descr => gorolla($5),
		type => 'method'
	};
	push @{${$class}{methods}}, $function;
} ],

[ 'WSLUA_METAMETHOD\s+([A-Za-z]+)(__[a-z0-9]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ":$2";
	my ($c,$d) = ($1,$5);
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $name,
		descr => gorolla($5),
		type => 'metamethod'
	};
	push @{${$class}{methods}}, $function;
} ],

[ '#define WSLUA_(OPT)?ARG_([a-z0-9_]+)_([A-Z0-9]+)\s+\d+' . $TRAILING_COMMENT_RE,
sub {
	deb ">a=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = $1 eq 'OPT' ? "[$3]" : $3;
	push @{${$function}{arglist}} , $name;
	${${$function}{args}}{$name} = {descr=>$6,}
} ],

[ '\057\052\s*WSLUA_(OPT)?ARG_([A-Za-z0-9_]+)_([A-Z0-9]+)\s*(.*?)\052\057',
sub {
	deb ">a=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = $1 eq 'OPT' ? "[$3]" : $3;
	push @{${$function}{arglist}} , $name;
	${${$function}{args}}{$name} = {descr=>$4,}
} ],

[ '#define WSLUA_(OPT)?ARG_([A-Za-z]+)_([a-z_]+)_([A-Z0-9]+)\s+\d+' . $TRAILING_COMMENT_RE,
sub {
	deb ">ca=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = $1 eq 'OPT' ? "[$4]" : $4;
	push @{${$function}{arglist}} , $name;
	${${$function}{args}}{$name} = {descr=>$7,optional => $1 eq '' ? 1 : 0 }
} ],

[ '/\052\s+WSLUA_ATTRIBUTE\s+([A-Za-z]+)_([a-z_]+)\s+([A-Z]*)\s*(.*?)\052/',
sub {
	deb ">at=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ".$2";
	push @{${$class}{attributes}}, { name => $name, descr => gorolla($4), mode=>$3 };
} ],

[ 'WSLUA_ATTR_GET\s+([A-Za-z]+)_([a-z_]+).*?' . $TRAILING_COMMENT_RE,
sub {
	deb ">at=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ".$2";
	push @{${$class}{attributes}}, { name => $name, descr => gorolla($4), mode=>$3 };
} ],

[ '/\052\s+WSLUA_MOREARGS\s+([A-Za-z_]+)\s+(.*?)\052/',
sub {
	deb ">ma=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{arglist}} , "...";
	${${$function}{args}}{"..."} = {descr=>gorolla($2)}
} ],

[ 'WSLUA_(FINAL_)?RETURN\050\s*.*?\s*\051\s*;' . $TRAILING_COMMENT_RE,
sub {
	deb ">fr=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{returns}} , gorolla($4) if $4 ne '';
} ],

[ '\057\052\s*_WSLUA_RETURNS_\s*(.*?)\052\057',
sub {
	deb ">fr2=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{returns}} , gorolla($1) if $1 ne '';
} ],

[ 'WSLUA_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+),' . $QUOTED_RE ,
sub {
	deb ">e=$1=$2=$3=$4=$5=$6=$7=\n";
	my $errors;
	unless (exists ${$function}{errors}) {
		$errors =  ${$function}{errors} = [];
	} else {
		$errors = ${$function}{errors};
	}
	push @{$errors}, gorolla($4);
} ],

[ 'WSLUA_(OPT)?ARG_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+)\s*,\s*([A-Z0-9]+)\s*,\s*' . $QUOTED_RE,
sub {
	deb ">ae=$1=$2=$3=$4=$5=$6=$7=\n";
	my $errors;
	unless (exists ${${${$function}{args}}{$5}}{errors}) {
		$errors =  ${${${$function}{args}}{$5}}{errors} = [];
	} else {
		$errors = ${${${$function}{args}}{$5}}{errors};
	}
	push @{$errors}, gorolla($6);
} ],

);

my $anymatch = '(^ThIsWiLlNeVeRmAtCh$';
for (@control) {
	$anymatch .= "|${$_}[0]";
}
$anymatch .= ')';

# for each file given in the command line args
my $file;
while ( $file =  shift) {

	next unless -f $file;

	%module = ();

	my $docfile = $file;
	$docfile =~ s#.*/##;
	$docfile =~ s/\.c$/.$out_extension/;

	open C, "< $file" or die "Can't open input file $file: $!";
	open D, "> wsluarm_src/$docfile" or die "Can't open output file wsluarm_src/$docfile: $!";

	my $b = '';
	$b .= $_ while (<C>);

	while ($b =~ /$anymatch/ms ) {
		my $match = $1;
# print "\n-----\n$match\n-----\n";
		for (@control) {
			my ($re,$f) = @{$_};
			if ( $match =~ /$re/ms) {
				&{$f}();
				$b =~ s/.*?$re//ms;
				last;
			}
		}
	}

	$modules{$module{name}} = $docfile;

	printf D ${$template_ref}{module_header}, $module{name}, $module{name};
	if ( exists  ${$template_ref}{module_desc} ) {
		printf D ${$template_ref}{module_desc}, $module{descr}, $module{descr};
	}

	for my $cname (sort keys %classes) {
		my $cl = $classes{$cname};
		printf D ${$template_ref}{class_header}, $cname, $cname;

		if ( ${$cl}{descr} ) {
			printf D ${$template_ref}{class_desc} , ${$cl}{descr};
		}

		if ( $#{${$cl}{constructors}} >= 0) {
#			printf D ${$template_ref}{class_constructors_header}, $cname, $cname;

			for my $c (@{${$cl}{constructors}}) {
				function_descr($c);
			}

#			printf D ${$template_ref}{class_constructors_footer}, $cname, $cname;
		}

		if ( $#{${$cl}{methods}} >= 0) {
#			printf D ${$template_ref}{class_methods_header}, $cname, $cname;

			for my $m (@{${$cl}{methods}}) {
				function_descr($m);
			}

#			printf D ${$template_ref}{class_methods_footer}, $cname, $cname;
		}

		if ( $#{${$cl}{attributes}} >= 0) {
			for my $a (@{${$cl}{attributes}}) {
				my $a_id = ${$a}{name};
				$a_id =~ s/[^a-zA-Z0-9]/_/g;
				printf D ${$template_ref}{class_attr_header}, $a_id, ${$a}{name};
				printf D ${$template_ref}{class_attr_descr}, ${$a}{descr}, ${$a}{descr} if ${$a}{descr};
				printf D ${$template_ref}{class_attr_footer}, ${$a}{name}, ${$a}{name};

			}
		}

		if (exists ${$template_ref}{class_footer}) {
			printf D ${$template_ref}{class_footer}, $cname, $cname;
		}

	}

	if ($#functions >= 0) {
		printf D ${$template_ref}{non_method_functions_header}, $module{name};

		for my $f (@functions) {
			function_descr($f);
		}

		print D ${$template_ref}{non_method_functions_footer};
	}

	%classes = ();
	$class = undef;
	$function = undef;
	@functions = ();
	close C;

	printf D ${$template_ref}{module_footer}, $module{name};

	close D;
}

#my $wsluarm = '';
#open B, "< template-wsluarm.xml";
#$wsluarm .= $_ while(<B>);
#close B;
#
#my $ents = '';
#my $txt = '';
#
#for my $module_name (sort keys %modules) {
#	$ents .= <<"_ENT";
#	<!ENTITY $module_name SYSTEM "wsluarm_src/$modules{$module_name}">
#_ENT
#	$txt .= "&$module_name;\n";
#}
#
#$wsluarm =~ s/<!-- WSLUA_MODULE_ENTITIES -->/$ents/;
#$wsluarm =~ s/<!-- WSLUA_MODULE_TEXT -->/$txt/;
#
#open X, "> wsluarm.xml";
#print X $wsluarm;
#close X;

sub function_descr {
	my $f = $_[0];
	my $label = $_[1];

	if (defined $label ) {
		$label =~ s/>/&gt;/;
		$label =~ s/</&lt;/;
		my $section_name =  ${$f}{section_name};
		$section_name =~ s/[^a-zA-Z0-9]/_/g;

		printf D ${$template_ref}{function_header}, $section_name, $label;
	} else {
		my $arglist = '';

		for (@{ ${$f}{arglist} }) {
			my $a = $_;
			$a =~ tr/A-Z/a-z/;
			$arglist .= "$a, ";
		}

		$arglist =~ s/, $//;
		my $section_name =  "${$f}{name}($arglist)";
		$section_name =~ s/[^a-zA-Z0-9]/_/g;

		printf D ${$template_ref}{function_header}, $section_name , "${$f}{name}($arglist)";
	}

	printf D ${$template_ref}{function_descr}, ${$f}{descr} if ${$f}{descr};

	print D ${$template_ref}{function_args_header} if $#{${$f}{arglist}} >= 0;

	for my $argname (@{${$f}{arglist}}) {
		my $arg = ${${$f}{args}}{$argname};
		$argname =~ tr/A-Z/a-z/;
		$argname =~ s/\[(.*)\]/$1 (optional)/;

		printf D ${$template_ref}{function_arg_header}, $argname, $argname;
		printf D ${$template_ref}{function_arg_descr}, ${$arg}{descr} , ${$arg}{descr} if ${$arg}{descr};

		if ( $#{${$arg}{errors}} >= 0) {
			printf D ${$template_ref}{function_argerror_header}, $argname, $argname;
			printf D ${$template_ref}{function_argerror}, $_, $_ for @{${$arg}{errors}};
			printf D ${$template_ref}{function_argerror_footer}, $argname, $argname;
		}

		printf D ${$template_ref}{function_arg_footer}, $argname, $argname;

	}

	print D ${$template_ref}{function_args_footer} if $#{${$f}{arglist}} >= 0;

	if ( $#{${$f}{returns}} >= 0) {
		printf D ${$template_ref}{function_returns_header}, ${$f}{name};
		printf D ${$template_ref}{function_returns}, $_ for @{${$f}{returns}};
		printf D ${$template_ref}{function_returns_footer}, ${$f}{name};
	}

	if ( $#{${$f}{errors}} >= 0) {
		my $sname = exists ${$f}{section_name} ? ${$f}{section_name} : ${$f}{name};

		printf D ${$template_ref}{function_errors_header}, $sname;
		printf D ${$template_ref}{function_errors}, $_ for @{${$f}{errors}};
		printf D ${$template_ref}{function_errors_footer}, ${$f}{name};
	}

	if (not defined $label ) {
		$label = '';
	}

	printf D ${$template_ref}{function_footer}, $label, $label;

}
