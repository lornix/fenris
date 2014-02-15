// signal() test... erm, I had to use assembly because
// new libc calls rt_sigaction instead :/

void signalek(int a,void* ptr) {
  long __res;
  __asm__ volatile ("int $0x80"
                    : "=a" (__res) \
 	            : "0" (48), "b" (a), "c" (ptr));
}


		
dupajeza() {
	printf("juhu\n");
}

main() {
	signalek(10,dupajeza);
	signalek(10,123456);
	signalek(10,0);
	signalek(10,123456);
}
