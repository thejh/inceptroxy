typedef int data_filter; // FIXME!

void reload_blacklist();
int bl_check(char *host);
data_filter *bl_get_data_filter(char *url, int url_size);
