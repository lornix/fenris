fufkcja(char* b2) {
	 char buf[10];
buf[2]=12;
b2[2]=34;
printf("l0 %x l-1 %x\n",buf,b2);
}

fuf() {
  char buf[10];
  buf[1]=1;
  fufkcja(buf);
}
	
main() { fuf(); }
