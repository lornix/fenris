// Test execve() reporting.

main() {
  execl("/bin/nonexisting","nope",0);
  execl("/bin/ls","ls",0);
}
