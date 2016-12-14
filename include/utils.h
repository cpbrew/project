#include <string>
using std::string;

void addPadding(string &, size_t);
string removePadding(string);
string btoh(const char *b, size_t len);
void ltob(uint64_t, unsigned char *);
void btol(const unsigned char *, uint64_t *);