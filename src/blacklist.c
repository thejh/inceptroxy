#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


char **blacklist = NULL;
int blacklist_size = 0;

void reload_domain_blacklist() {
  FILE *f = fopen("../conf/domains.blacklist", "r");
  char line[1024];
  blacklist_size = 0;
  while (fgets(line, 1024, f) != NULL) {
    if (strlen(line) < 3 || line[0] == '#') continue;
    blacklist_size++;
  }
  blacklist = malloc(sizeof(char *) * blacklist_size);
  rewind(f);
  int i = 0;
  while (fgets(line, 1024, f) != NULL) {
    if (strlen(line) < 3 || line[0] == '#') continue;
    char *r_i = strchr(line, '\r');
    char *n_i = strchr(line, '\n');
    if (r_i != NULL) *r_i = '\0';
    if (n_i != NULL) *n_i = '\0';
    blacklist[i++] = strdup(line);
  }
  assert(i == blacklist_size);
  fclose(f);
}

int bl_check(char *host) {
  char predotted_bl_entry[1030];
  predotted_bl_entry[0] = '.';
  
  for (int i=0; i<blacklist_size; i++) {
    if (strcmp(host, blacklist[i]) == 0) return 1;
    
    strcpy(predotted_bl_entry+1, blacklist[i]);
    if (memcmp(host + (strlen(host) - strlen(predotted_bl_entry)), predotted_bl_entry, strlen(predotted_bl_entry)+1) == 0) return 1;
  }
  
  return 0;
}
