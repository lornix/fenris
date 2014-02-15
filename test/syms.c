// Local symbols test

dwa(char* x) { printf("%s\n",x); }
trzy(void* x) { printf("%x\n",x); }

int fiutk;

main() {
	printf("Jestem.\n");
	trzy(dwa);
	dwa("malym");
	trzy(dwa);
	trzy(&fiutk);
}
