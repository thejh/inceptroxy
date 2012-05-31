#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


struct bl_entry {
  char *domain;
  char forbidden;
};


struct bl_entry *blacklist = NULL;
int blacklist_size = 0;


static struct bl_entry *get_bl_entry(char *host) {
  char predotted_bl_entry[1030];
  predotted_bl_entry[0] = '.';
  
  for (int i=0; i<blacklist_size; i++) {
    if (strcmp(host, blacklist[i].domain) == 0) return &blacklist[i];
    
    strcpy(predotted_bl_entry+1, blacklist[i].domain);
    if (memcmp(host + (strlen(host) - strlen(predotted_bl_entry)), predotted_bl_entry, strlen(predotted_bl_entry)+1) == 0)
      return &blacklist[i];
  }
  
  return NULL;
}

void reload_blacklist() {
  FILE *f = fopen("../conf/domains.blacklist", "r");
  char line[1024];
  blacklist_size = 0;
  while (fgets(line, 1024, f) != NULL) {
    if (strlen(line) < 3 || line[0] == '#') continue;
    blacklist_size++;
  }
  blacklist = malloc(sizeof(struct bl_entry) * blacklist_size);
  rewind(f);
  int i = 0;
  while (fgets(line, 1024, f) != NULL) {
    if (strlen(line) < 3 || line[0] == '#') continue;
    char *r_i = strchr(line, '\r');
    char *n_i = strchr(line, '\n');
    if (r_i != NULL) *r_i = '\0';
    if (n_i != NULL) *n_i = '\0';
    blacklist[i].forbidden = 1;
    blacklist[i++].domain = strdup(line);
  }
  assert(i == blacklist_size);
  fclose(f);
}

int bl_check(char *host) {
  struct bl_entry *e = get_bl_entry(host);
  if (e == NULL) return 0;
  return e->forbidden;
}
