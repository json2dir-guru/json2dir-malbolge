/* json2dir evaluator, compiled to Malbolge Unshackled:
 *   8cc (ELVM) -> EIR -> elc -hell -> HeLL -> LMFAO -> json2dir.mal
 * Reads the JSON document byte by byte from stdin, validates all of it (UTF-8, strict JSON,
 * json2dir rules) and prints a shell script that ends with "# json2dir: end".
 * On error it prints only "json2dir: <message>" (Malbolge has no stderr and no exit status).
 *
 * Written for the ELVM target: words are 24-bit, char == int, and multiplication, division,
 * shifts and bit operations are slow library loops, so the code sticks to +, -, comparisons
 * and int arrays. Comparisons are unsigned, so the -1 sentinels are only tested with == / !=.
 * ELVM's getchar() reports a NUL byte as EOF; a raw NUL is invalid JSON anyway. */

#include <stdlib.h> /* ELVM: malloc, exit and the __builtin_mul / __builtin_div helpers */

int getchar(void);
int putchar(int c);

#define MAXIN 1048576
#define MAXNODES 65536

int *in;    /* the input bytes */
int inlen;
int pos;
int *pool;  /* decoded strings */
int plen;
/* nodes: kind 1 = object, 2 = file, 3 = link, 4 = script */
int *kind;
int *nstart; /* name in pool */
int *nlen;
int *vstart; /* content / link target in pool */
int *vlen;
int *first;  /* first child (sorted), -1 if none */
int *next;   /* next sibling */
int nnodes;
int *path;   /* current path bytes */
int pathlen;

void puts_raw(char *s) {
  while (*s) { putchar(*s); s++; }
}

void fail(char *msg) {
  puts_raw("json2dir: ");
  puts_raw(msg);
  putchar(10);
  exit(1);
}

/* section 3: strict UTF-8 (no overlong forms, no surrogates, nothing above U+10FFFF) */
void check_utf8(void) {
  int i = 0;
  int b;
  int b1;
  int n;
  while (i < inlen) {
    b = in[i];
    if (b < 128) { i++; continue; }
    if (b < 194 || b > 244) fail("input is not valid UTF-8");
    if (b < 224) n = 1; else if (b < 240) n = 2; else n = 3;
    if (i + n >= inlen) fail("input is not valid UTF-8");
    b1 = in[i + 1];
    if (b1 < 128 || b1 > 191) fail("input is not valid UTF-8");
    if (b == 224 && b1 < 160) fail("input is not valid UTF-8");
    if (b == 237 && b1 > 159) fail("input is not valid UTF-8");
    if (b == 240 && b1 < 144) fail("input is not valid UTF-8");
    if (b == 244 && b1 > 143) fail("input is not valid UTF-8");
    if (n >= 2 && (in[i + 2] < 128 || in[i + 2] > 191)) fail("input is not valid UTF-8");
    if (n == 3 && (in[i + 3] < 128 || in[i + 3] > 191)) fail("input is not valid UTF-8");
    i = i + n + 1;
  }
}

void skip_ws(void) {
  int b;
  while (pos < inlen) {
    b = in[pos];
    if (b == 32 || b == 9 || b == 10 || b == 13) pos++;
    else return;
  }
}

int hexval(void) {
  int v = 0;
  int k;
  int b;
  for (k = 0; k < 4; k++) {
    if (pos >= inlen) fail("input is not valid JSON");
    b = in[pos];
    pos++;
    v = v + v; v = v + v; v = v + v; v = v + v;
    if (b >= '0' && b <= '9') v = v + b - '0';
    else if (b >= 'a' && b <= 'f') v = v + b - 'a' + 10;
    else if (b >= 'A' && b <= 'F') v = v + b - 'A' + 10;
    else fail("input is not valid JSON");
  }
  return v;
}

void put_utf8(int cp) {
  if (cp < 128) { pool[plen] = cp; plen++; return; }
  if (cp < 2048) {
    pool[plen] = 192 + cp / 64; pool[plen + 1] = 128 + cp % 64; plen = plen + 2; return;
  }
  if (cp < 65536) {
    pool[plen] = 224 + cp / 4096; pool[plen + 1] = 128 + cp / 64 % 64; pool[plen + 2] = 128 + cp % 64;
    plen = plen + 3; return;
  }
  pool[plen] = 240 + cp / 262144; pool[plen + 1] = 128 + cp / 4096 % 64;
  pool[plen + 2] = 128 + cp / 64 % 64; pool[plen + 3] = 128 + cp % 64;
  plen = plen + 4;
}

/* parses a JSON string at pos into the pool; returns its start, sets *len */
int parse_string(int *len) {
  int start = plen;
  int b;
  int cp;
  int lo;
  if (pos >= inlen || in[pos] != '"') fail("input is not valid JSON");
  pos++;
  for (;;) {
    if (pos >= inlen) fail("input is not valid JSON");
    b = in[pos];
    pos++;
    if (b == '"') break;
    if (b < 32) fail("input is not valid JSON");
    if (b != 92) { pool[plen] = b; plen++; continue; }
    if (pos >= inlen) fail("input is not valid JSON");
    b = in[pos];
    pos++;
    if (b == '"' || b == 92 || b == '/') { pool[plen] = b; plen++; }
    else if (b == 'b') { pool[plen] = 8; plen++; }
    else if (b == 'f') { pool[plen] = 12; plen++; }
    else if (b == 'n') { pool[plen] = 10; plen++; }
    else if (b == 'r') { pool[plen] = 13; plen++; }
    else if (b == 't') { pool[plen] = 9; plen++; }
    else if (b == 'u') {
      cp = hexval();
      if (cp >= 56320 && cp <= 57343) fail("input contains an unpaired surrogate escape");
      if (cp >= 55296 && cp <= 56319) {
        if (pos + 1 >= inlen || in[pos] != 92 || in[pos + 1] != 'u')
          fail("input contains an unpaired surrogate escape");
        pos = pos + 2;
        lo = hexval();
        if (lo < 56320 || lo > 57343) fail("input contains an unpaired surrogate escape");
        cp = 65536 + (cp - 55296) * 1024 + (lo - 56320);
      }
      put_utf8(cp);
    }
    else fail("input is not valid JSON");
  }
  *len = plen - start;
  return start;
}

/* -1, 0, 1: byte order of two pool strings */
int cmp(int a, int al, int b, int bl) {
  int i = 0;
  while (i < al && i < bl) {
    if (pool[a + i] != pool[b + i]) {
      if (pool[a + i] < pool[b + i]) return -1;
      return 1;
    }
    i++;
  }
  if (al < bl) return -1;
  if (al > bl) return 1;
  return 0;
}

int eq_lit(int s, int l, char *lit) {
  int i = 0;
  while (lit[i]) {
    if (i >= l || pool[s + i] != lit[i]) return 0;
    i++;
  }
  return i == l;
}

int has_byte(int s, int l, int b) {
  int i;
  for (i = 0; i < l; i++) if (pool[s + i] == b) return 1;
  return 0;
}

int new_node(int k) {
  int n = nnodes;
  if (n >= MAXNODES) fail("too many entries");
  nnodes++;
  kind[n] = k;
  first[n] = -1;
  next[n] = -1;
  return n;
}

int parse_value(void);

/* object at pos; children are inserted in byte order of their names */
int parse_object(void) {
  int o = new_node(1);
  int ns;
  int nl;
  int c;
  int p;
  int q;
  int r;
  pos++; /* '{' */
  skip_ws();
  if (pos < inlen && in[pos] == '}') { pos++; return o; }
  for (;;) {
    skip_ws();
    ns = parse_string(&nl);
    if (nl == 0 || eq_lit(ns, nl, ".") || eq_lit(ns, nl, "..") || has_byte(ns, nl, '/') || has_byte(ns, nl, 0))
      fail("invalid name");
    skip_ws();
    if (pos >= inlen || in[pos] != ':') fail("input is not valid JSON");
    pos++;
    skip_ws();
    c = parse_value();
    nstart[c] = ns;
    nlen[c] = nl;
    p = -1;
    q = first[o];
    for (;;) {
      if (q == -1) break;
      r = cmp(nstart[q], nlen[q], ns, nl);
      if (r == 0) fail("duplicate name");
      if (r == 1) break;
      p = q;
      q = next[q];
    }
    next[c] = q;
    if (p == -1) first[o] = c; else next[p] = c;
    skip_ws();
    if (pos >= inlen) fail("input is not valid JSON");
    if (in[pos] == ',') { pos++; continue; }
    if (in[pos] == '}') { pos++; return o; }
    fail("input is not valid JSON");
  }
  return o;
}

int parse_value(void) {
  int b;
  int n;
  int ks;
  int kl;
  int vs;
  int vl;
  if (pos >= inlen) fail("input is not valid JSON");
  b = in[pos];
  if (b == '{') return parse_object();
  if (b == '"') {
    n = new_node(2);
    vstart[n] = parse_string(&vl);
    vlen[n] = vl;
    return n;
  }
  if (b == '[') {
    pos++;
    skip_ws();
    if (pos >= inlen || in[pos] != '"') fail("an array must be [\"link\", target] or [\"script\", content]");
    ks = parse_string(&kl);
    skip_ws();
    if (pos >= inlen || in[pos] != ',') fail("an array must be [\"link\", target] or [\"script\", content]");
    pos++;
    skip_ws();
    if (pos >= inlen || in[pos] != '"') fail("an array must be [\"link\", target] or [\"script\", content]");
    vs = parse_string(&vl);
    skip_ws();
    if (pos >= inlen || in[pos] != ']') fail("an array must be [\"link\", target] or [\"script\", content]");
    pos++;
    if (eq_lit(ks, kl, "link")) {
      if (has_byte(vs, vl, 0)) fail("a link target cannot contain NUL");
      n = new_node(3);
    } else if (eq_lit(ks, kl, "script")) {
      n = new_node(4);
    } else {
      fail("unknown array kind");
    }
    vstart[n] = vs;
    vlen[n] = vl;
    return n;
  }
  fail("only objects, strings and [kind, string] arrays are allowed");
  return 0;
}

/* a single-quoted shell word; NUL bytes split it into separate words */
void put_quoted(int *s, int l) {
  int i;
  int b;
  putchar(39);
  for (i = 0; i < l; i++) {
    b = s[i];
    if (b == 39) { putchar(39); putchar(92); putchar(39); putchar(39); }
    else if (b == 0) { putchar(39); putchar(32); putchar(39); }
    else putchar(b);
  }
  putchar(39);
}

void emit(int o) {
  int c = first[o];
  int save;
  int i;
  int k;
  while (c != -1) {
    save = pathlen;
    path[pathlen] = '/';
    pathlen++;
    for (i = 0; i < nlen[c]; i++) { path[pathlen] = pool[nstart[c] + i]; pathlen++; }
    k = kind[c];
    if (k == 1) puts_raw("_d ");
    else if (k == 2) puts_raw("_w ");
    else if (k == 3) puts_raw("_l ");
    else puts_raw("_x ");
    put_quoted(path, pathlen);
    if (k != 1) { putchar(32); put_quoted(pool + vstart[c], vlen[c]); }
    putchar(10);
    if (k == 1) emit(c);
    pathlen = save;
    c = next[c];
  }
}

int main(void) {
  int b;
  int root;
  in = malloc(MAXIN);
  pool = malloc(MAXIN);
  kind = malloc(MAXNODES);
  nstart = malloc(MAXNODES);
  nlen = malloc(MAXNODES);
  vstart = malloc(MAXNODES);
  vlen = malloc(MAXNODES);
  first = malloc(MAXNODES);
  next = malloc(MAXNODES);
  path = malloc(MAXIN);
  inlen = 0;
  for (;;) {
    b = getchar();
    if (b == -1) break;
    if (inlen >= MAXIN) fail("input too large");
    in[inlen] = b;
    inlen++;
  }
  check_utf8();
  pos = 0;
  if (inlen >= 3 && in[0] == 239 && in[1] == 187 && in[2] == 191) pos = 3;
  skip_ws();
  if (pos >= inlen || in[pos] != '{') fail("the root of the document must be an object");
  root = parse_value();
  skip_ws();
  if (pos != inlen) fail("input is not valid JSON");
  puts_raw("set -eu\n"
           "_f(){ printf 'json2dir: cannot create %s\\n' \"$1\" >&2;exit 1;}\n"
           "_c(){ if [ -L \"$1\" ];then rm -f -- \"$1\"||_f \"$1\";elif [ -d \"$1\" ];then printf 'json2dir: a directory is in the way: %s\\n' \"$1\" >&2;exit 1;elif [ -e \"$1\" ];then rm -f -- \"$1\"||_f \"$1\";fi;}\n"
           "_d(){ if [ -L \"$1\" ]||{ [ -e \"$1\" ]&&[ ! -d \"$1\" ];};then rm -f -- \"$1\"||_f \"$1\";fi;[ -d \"$1\" ]||mkdir -- \"$1\"||_f \"$1\";}\n"
           "_w(){ _c \"$1\";_p=$1;shift;{ printf %s \"$1\";shift;for _q;do printf '\\000%s' \"$_q\";done;}>\"$_p\"||_f \"$_p\";}\n"
           "_x(){ _w \"$@\";chmod a+x -- \"$1\"||_f \"$1\";}\n"
           "_l(){ _c \"$1\";ln -s -- \"$2\" \"$1\"||_f \"$1\";}\n");
  path[0] = '.';
  pathlen = 1;
  emit(root);
  puts_raw("# json2dir: end\n");
  return 0;
}
