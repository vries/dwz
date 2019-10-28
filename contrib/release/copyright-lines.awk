BEGIN {
    start=0
}

/Copyright \(C\).*[.]/ {
    print
    next
}

/Copyright \(C\)/ {
    start=1
    printf $0
    next
}

/[.]/ {
    if (start == 0)
	next
    print
    start=0
}

// {
    if (start == 0)
	next
    printf $0
}
