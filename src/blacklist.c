#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "helpers.h"
#include "blacklist.h"


struct bl_entry {
  char *domain;
  char forbidden;
  char filter;
};


struct bl_entry *blacklist = NULL;
int blacklist_size = 0;

char **script_badwords = NULL;
int script_badwords_size = 0;


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

static struct bl_entry *get_bl_entry_by_url(char *url, int url_size) {
  // WARNING: duplicate code! (see main.c)
  char *hostname_end = memchr(url + 7, '/', url_size - 7);
  assert(hostname_end != NULL);
  char hostname[hostname_end - url - 7 + 1];
  memcpy(hostname, url + 7, hostname_end - url - 7);
  hostname[hostname_end - url - 7] = '\0';
  return get_bl_entry(hostname);
}

void reload_blacklist() {
  // domains blacklist
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
    if (line[1] != ' ') assert(0 /*invalid configuration file*/);
    char *r_i = strchr(line, '\r');
    char *n_i = strchr(line, '\n');
    if (r_i != NULL) *r_i = '\0';
    if (n_i != NULL) *n_i = '\0';
    blacklist[i].domain = strdup(line+2);
    switch (line[0]) {
      case 'b': {
        blacklist[i].forbidden = 1;
        blacklist[i].filter = 0;
        break;
      }
      case 'f': {
        blacklist[i].forbidden = 0;
        blacklist[i].filter = 1;
        break;
      }
    }
    i++;
  }
  assert(i == blacklist_size);
  fclose(f);
  
  // script badwords
  f = fopen("../conf/script_texts.blacklist", "r");
  script_badwords_size = 0;
  while (fgets(line, 1024, f) != NULL) {
    if (strlen(line) < 3) continue;
    script_badwords_size++;
  }
  script_badwords = malloc(sizeof(char *) * script_badwords_size);
  rewind(f);
  i = 0;
  while (fgets(line, 1024, f) != NULL) {
    if (strlen(line) < 3) continue;
    char *r_i = strchr(line, '\r');
    char *n_i = strchr(line, '\n');
    if (r_i != NULL) *r_i = '\0';
    if (n_i != NULL) *n_i = '\0';
    script_badwords[i++] = strdup(line);
  }
  assert(i == script_badwords_size);
  fclose(f);
}

int bl_check(char *host) {
  struct bl_entry *e = get_bl_entry(host);
  if (e == NULL) return 0;
  return e->forbidden;
}

static char simple_data_filter(char **buf, size_t *buf_len) {
  for (int i=0; i<script_badwords_size; i++) {
    if (memmem(*buf, *buf_len, script_badwords[i], strlen(script_badwords[i])) != NULL) {
      *buf = strdup("</script>");
      *buf_len = 9;
      return 0;
    }
  }
  char *newbuf = malloc(*buf_len);
  memcpy(newbuf, *buf, *buf_len);
  *buf = newbuf;
  return 0;
}

data_filter *bl_get_data_filter(char *url, int url_size) {
  struct bl_entry *e = get_bl_entry_by_url(url, url_size);
  if (e == NULL || e->filter == 0) return NULL;
  
  return simple_data_filter;
}
