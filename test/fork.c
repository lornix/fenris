// trivial fork tracing.

main() {
  int i;
  i=fork();
  sleep(10);
  sleep(10);
  sleep(10);
  sleep(10);
  sleep(10);

//  if (!i) execl("/bin/ls","ls",0);
}

