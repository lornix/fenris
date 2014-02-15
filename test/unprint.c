// Unprintable characters filtering test

main() {
	open("/dev/\n\"blah\xff bounc",0);
}
