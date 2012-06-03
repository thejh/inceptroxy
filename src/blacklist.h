typedef char data_filter(char **buf, size_t *buf_len); // FIXME!

void reload_blacklist();
int bl_check(char *host);
data_filter *bl_get_data_filter(char *url, int url_size);
