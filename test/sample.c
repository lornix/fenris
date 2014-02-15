// Just a sample code for ragnarok.

innafunkcja(char* x) {
	strcpy(x,"this is just a test");
}

main() {
	char* buf;
        buf=malloc(100);
        bzero(buf,100);
	innafunkcja(buf);
	printf("This is a result: %s\n",buf);
free(buf);
}
