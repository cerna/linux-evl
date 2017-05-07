#! /bin/sh

set -e

shift

awk '
match($0, /STEELY_SYSCALL\([^,]*,[ \t]*[^,]*/)  {
	str=substr($0, RSTART + 15, RLENGTH - 15)
	match(str, /[^, \t]*/)
	syscall=substr(str, RSTART, RLENGTH)

	if (syscall == "") {
		print "Failed to find syscall name in line " $0 > "/dev/stderr"
		exit 1
	}

	calls = calls "	__STEELY_CALL_ENTRY(" syscall ") \\\n"
	modes = modes "	__STEELY_MODE(" str ") \\\n"
	next
}

/STEELY_SYSCALL\(/  {
	print "Failed to parse line " $0 > "/dev/stderr"
	exit 1
}

END {
	print "#define __STEELY_CALL_ENTRIES \\\n" calls "	/* end */"
	print "#define __STEELY_CALL_MODES \\\n" modes "	/* end */"
}
' $*
