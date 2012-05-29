#define _POSIX_SOURCE
#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <signal.h>

#include <libev/ev.h>

#include "../deps/http-parser/http_parser.h"

#include "memory.h"
#include "headers.h"
#include "ev_helpers.h"
#include "helpers.h"
#include "outstream.h"
#include "easy_hashtable.h"
#include "blacklist.h"


#define READ_CHUNK_SIZE (64 * 1024)
#define IDLE_AGENT_TIMEOUT 60
#define PRINT_URLS

// FIXME this depends a lot on stuff in http_parser.h
char *http_method_strings[26] = {
#define XX(num, name, string) #string,
  HTTP_METHOD_MAP(XX)
#undef XX
};

void printbuf(const char *format, const char *buf, size_t len) {
  char *cstr = malloc(len+1);
  memcpy(cstr, buf, len);
  cstr[len] = 0;
  printf(format, cstr);
  free(cstr);
}

//#define DEBUG_ON
#ifdef DEBUG_ON
  #define printd printf
  #define printbufd printbuf
#else
  void noop(char *x, ...) {}
  #define printd noop
  #define printbufd noop
#endif




struct client_fd_watcher;

void kill_client(struct client_fd_watcher *client);
void response_tcp_data_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void agent_outstream_error_cb(struct outstream *o);
void process_client_data(struct client_fd_watcher *w, char *data, int read_data);





// Contains an ev_io watcher that listens for incoming connections
// on the port-bound server socket.
struct listen_fd_watcher {
  struct ev_io watcher;
};

// Represents the state of a proxy<-->server connection.
struct http_agent {
  struct ev_io watcher;
  struct ev_timer idle_timeout;
  http_parser parser;
  struct outstream outstream;
  char *host;
  
  struct client_fd_watcher *client;
  
  struct http_header *response_headers;
  
  struct http_agent *prev, *next;
  char is_free; // 0 or 1
};

// Represents the state of a browser<-->proxy connection.
struct client_fd_watcher {
  struct ev_io watcher;
  http_parser parser;
  struct outstream outstream;
  struct http_agent *agent;
  
  char *url;
  int url_size;
  struct http_header *request_headers;
  
  // antipipelining
  char *pending_data;
  int pending_data_length;
  char parser_paused;
  char parser_dontpause;
};

// host:port -> first idle
GHashTable *idle_agents_by_host;

// will free()!
void kill_agent(struct http_agent *agent) {
  if (agent->client != NULL) {
    agent->client->agent = NULL;
    kill_client(agent->client);
  }
  outstream_nuke(&agent->outstream);
  ev_io_stop(ev_default_loop(0), &agent->watcher);
  free_headers(&agent->response_headers);
  close(agent->watcher.fd);
  
  if (agent->is_free == 1) {
    if (agent->next != NULL) agent->next->prev = agent->prev;
    if (agent->prev != NULL) agent->prev->next = agent->next;
    
    // If we were the head, update the HT entry.
    if (agent->prev == NULL) ht_update(idle_agents_by_host, agent->host, agent->next);
    
    ev_timer_stop(ev_default_loop(0), &agent->idle_timeout);
  }
  
  free(agent->host);
  agent->host = "THIS AGENT WAS FREED - IF YOU SEE THIS IN A BROKEN AGENT, YOU NOW KNOW WHY.";
  free(agent);
}

// might return NULL!
struct http_agent *get_agent(char *host, struct client_fd_watcher *client) {
  assert(client != NULL);
  struct http_agent *a = ht_lookup(idle_agents_by_host, host);
  if (a != NULL) {
    printd("*** recycling! ***\n");
    assert(a->prev == NULL);
    if (a->next != NULL) a->next->prev = NULL;
    ht_update(idle_agents_by_host, host, a->next);
    ev_timer_stop(ev_default_loop(0), &a->idle_timeout);
    assert(a->client == NULL);
    assert(strcmp(host, a->host) == 0);
    goto prepare_and_return;
  }
  
  struct addrinfo *host_service_info;
  // FIXME make DNS async?
  if (getaddrinfo(host, "80", NULL, &host_service_info) != 0) {
    return NULL;
  }
  
  int agent_fd = socket((host_service_info->ai_family == AF_INET6) ? PF_INET6 : PF_INET, SOCK_STREAM, host_service_info->ai_protocol/*can I do this? seems so*/);
  assert(agent_fd >= 0);
  unblock_fd(agent_fd);
  connect(agent_fd, host_service_info->ai_addr, host_service_info->ai_addrlen);
  freeaddrinfo(host_service_info);
  a = malloc(sizeof(struct http_agent));
  a->response_headers = NULL;
  ev_io_init(&a->watcher, response_tcp_data_cb, agent_fd, EV_READ);
  ev_io_start(ev_default_loop(0), &a->watcher);
  http_parser_init(&a->parser, HTTP_RESPONSE);
  outstream_init(&a->outstream, agent_fd, agent_outstream_error_cb);
  a->host = strdup(host);
  
prepare_and_return:
  a->prev = NULL;
  a->next = NULL;
  a->is_free = 0;
  assert(client->agent == NULL);
  client->agent = a;
  a->client = client;
  return a;
}

void agent_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
  struct http_agent *a = CASTUP(w, struct http_agent, idle_timeout);
  printd("agent timeout - destroying now.\n");
  kill_agent(a);
}

void recycle_agent(struct http_agent *a) {
  assert(a->client != NULL && a->client->agent == a);
  a->client->agent = NULL;
  a->client = NULL;
  
  assert(a->prev == NULL && a->next == NULL && a->is_free == 0);
  struct http_agent *next = ht_lookup(idle_agents_by_host, a->host);
  a->next = next;
  if (next != NULL) next->prev = a;
  a->is_free = 1;
  // leaving these lines here so that I can later wonder what. the. fuck. I was thinking...
  // if I had used git earlier, it could tell me at which time I wrote this :D
  //a->prev = NULL;
  //a->next = NULL;
  ht_update(idle_agents_by_host, a->host, a);
  
  ev_timer_init(&a->idle_timeout, agent_timeout_cb, IDLE_AGENT_TIMEOUT, 0);
  ev_timer_start(ev_default_loop(0), &a->idle_timeout);
}

// will free()!
void kill_client(struct client_fd_watcher *client) {
  assert(client->watcher.fd > 3 && client->watcher.events <= (EV_READ | EV_WRITE)); // fights wild pointers
  if (client->agent != NULL) {
    assert(client->agent->watcher.fd > 3 && client->agent->watcher.events <= (EV_READ | EV_WRITE)); // fights wild pointers
    client->agent->client = NULL;
    kill_agent(client->agent);
  }
  ev_io_stop(ev_default_loop(0), &client->watcher);
  outstream_nuke(&client->outstream);
  free(client->url);
  client->url = NULL;
  free_headers(&client->request_headers);
  close(client->watcher.fd);
  free(client);
}

void chunkify(char **data, size_t *len, int free_old) {
  if (*len == 0) {
    if (free_old) free(*data);
    *data = NULL;
    *len = 0;
    return;
  }
  
  char *lenstr;
  int lenlen = asprintf(&lenstr, "%X", (unsigned int) *len);
  
  char *olddata = *data;
  *data = malloc(lenlen + 2 + *len + 2);
  memcpy(*data, lenstr, lenlen);
  free(lenstr);
  (*data)[lenlen] = '\r';
  (*data)[lenlen+1] = '\n';
  memcpy(*data + lenlen + 2, olddata, *len);
  (*data)[lenlen + 2 + *len] = '\r';
  (*data)[lenlen + 2 + *len + 1] = '\n';
  *len = lenlen + 2 + *len + 2;
  if (free_old) free(olddata);
}

const char *final_chunk = "0\r\n\r\n";

int assert_0_http_data_cb(http_parser *p, const char *data, size_t size) { assert(0); }


int on_server_message_begin(http_parser *p) {
  struct http_agent *a = CASTUP(p, struct http_agent, parser);
  printd("on_server_message_begin\n");
  
  return 0;
}

int on_server_header_field(http_parser *p, const char *data, size_t size) {
  struct http_agent *a = CASTUP(p, struct http_agent, parser);
  printbufd("on_server_header_field: %s\n", data, size);
  
  headers_append_key(&a->response_headers, data, size);
  
  return 0;
}

int on_server_header_value(http_parser *p, const char *data, size_t size) {
  struct http_agent *a = CASTUP(p, struct http_agent, parser);
  printbufd("on_server_header_value: %s\n", data, size);
  
  headers_append_value(&a->response_headers, data, size);
  
  return 0;
}

int on_server_headers_complete(http_parser *p) {
  struct http_agent *a = CASTUP(p, struct http_agent, parser);
  printd("on_server_headers_complete\n");
  
  char *status_str;
  int status_len = asprintf(&status_str, "%i", p->status_code);
  
  int len = 0;
  len += 8 + 1 + status_len + 1 + 7/*PROXIED*/ + 2;
  { 
    struct http_header *h = a->response_headers;
    struct http_header **origin = &a->response_headers;
    while (h != NULL) {
      printd("SAVED RES HEADER: <<< %s: %s >>>\n", h->key, h->value);
      if (strcasecmp(h->key, "Content-Length") == 0 || strcasecmp(h->key, "Transfer-Encoding") == 0) {
        free(h->key);
        free(h->value);
        *origin = h->next; // anchestry magic! my child shall be your child, my father,
        free(h);           // so that I can go in peace.
        h = *origin;
        continue;
      }
      len += strlen(h->key) + 2 + strlen(h->value) + 2;
      origin = &h->next;
      h = h->next;
    }
    
    headers_append_key(&a->response_headers, "Transfer-Encoding", 17);
    headers_append_value(&a->response_headers, "chunked", 7);
    len += 17+2+7+2;
  }
  len += 2;
  
  char *buf = malloc(len);
  char *b = buf;
  BUF_APPEND_STR(b, "HTTP/1.1 ");
  BUF_APPEND_STR(b, status_str);
  BUF_APPEND_STR(b, " PROXIED\r\n"); // well, yes - the HTTP parser doesn't give us the status string, so...
  {
    struct http_header *h = a->response_headers;
    while (h != NULL) {
      BUF_APPEND_STR(b, h->key);
      BUF_APPEND_STR(b, ": ");
      BUF_APPEND_STR(b, h->value);
      BUF_APPEND_STR(b, "\r\n");
      h = h->next;
    }
  }
  BUF_APPEND_STR(b, "\r\n");
  assert(b-buf == len);
  
  free_headers(&a->response_headers);
  outstream_send(&a->client->outstream, buf, len);
  
  free(status_str);
  return 0;
}

// XXX HOT CALLBACK! XXX
int on_server_body(http_parser *p, const char *data, size_t size) {
  struct http_agent *a = CASTUP(p, struct http_agent, parser);
  
  char *d = (char *) data; /* WARNING: Here, we promise not to touch *d before changing d! */
  
  assert(size != 0);
  chunkify(&d, &size, 0);
  
  outstream_send(&a->client->outstream, d, size);
  
  return 0;
}

int on_server_message_complete(http_parser *p) {
  struct http_agent *a = CASTUP(p, struct http_agent, parser);
  struct client_fd_watcher *w = a->client;
  printd("on_server_message_complete\n");
  
  char *data = malloc(strlen(final_chunk));
  memcpy(data, final_chunk, strlen(final_chunk));
  outstream_send(&a->client->outstream, data, strlen(final_chunk));
  
  // disassociate
  printd("unbinding agent\n");
  recycle_agent(a);
  
  // thaw incoming connection from browser
  if (w->parser_paused == 1) {
    w->parser_paused = 0;
    
    // open the pipes
    http_parser_pause(&w->parser, 0);
    alter_ev_io_events(&w->watcher, 1, EV_READ);
    
    // and melt the ice
    char *buf = w->pending_data;
    process_client_data(w, buf, w->pending_data_length);
    // fun fact: at this point, the connection could have already been frozen again :D
    free(buf);
  }
  
  return 0;
}


// incoming message begins now
int on_client_message_begin(http_parser *p) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  printd("on_client_message_begin\n");
  free(w->url);
  w->url = NULL;
  w->url_size = 0;
  return 0;
}

int on_client_url(http_parser *p, const char *data, size_t size) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  printbufd("on_client_url: %s\n", data, size);
  w->url = safe_realloc(w->url, w->url_size + size);
  memcpy(w->url + w->url_size, data, size);
  w->url_size += size;
  return 0;
}

int on_client_header_field(http_parser *p, const char *data, size_t length) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  printbufd("on_client_header_field: %s\n", data, length);
  
  headers_append_key(&w->request_headers, data, length);
  
  return 0;
}

int on_client_header_value(http_parser *p, const char *data, size_t length) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  printbufd("on_client_header_value: %s\n", data, length);
  
  headers_append_value(&w->request_headers, data, length);
  
  return 0;
}

http_parser_settings agent_parser_settings = {
  .on_message_begin = on_server_message_begin,
  .on_url = assert_0_http_data_cb,
  .on_header_field = on_server_header_field,
  .on_header_value = on_server_header_value,
  .on_headers_complete = on_server_headers_complete,
  .on_body = on_server_body,
  .on_message_complete = on_server_message_complete
};

// an agent got a TCP data chunk back from a server
void response_tcp_data_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
  struct http_agent *agent = CASTUP(watcher, struct http_agent, watcher);
  char buf[20*1024];
  ssize_t len = read(watcher->fd, buf, 20*1024);
  if (len == -1 && errno == EAGAIN) assert(0);
  if (len < 1) {
    if (len == -1) printf("in response_tcp_data_cb, killed agent - read() errored with %s\n", strerror(errno));
    kill_agent(agent);
    return;
  }
  int nparsed = http_parser_execute(&agent->parser, &agent_parser_settings, buf, len);
  if (agent->parser.upgrade) {
    // FIXME UPGRADE
  } else if (nparsed != len) {
    assert(0);
  }
}

void agent_outstream_error_cb(struct outstream *o) {
  struct http_agent *agent = CASTUP(o, struct http_agent, outstream);
  kill_agent(agent);
}

char *DENY_RESPONSE = "HTTP/1.1 403 *CENSORED*\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\n*CENSORED*";
char *INVAL_RESPONSE = "HTTP/1.1 400 INVALID\r\nConnection: keep-alive\r\nContent-Length: 7\r\n\r\ninvalid";

// headers are complete now - decide here what action to take
int on_client_headers_complete(http_parser *p) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  assert(w->watcher.fd > 3 && w->watcher.events <= (EV_READ | EV_WRITE)); // fights wild pointers
  printd("on_client_headers_complete\n");
  
  assert(w->url_size > 7 && memcmp(w->url, "http://", 7) == 0);
  char *hostname_end = memchr(w->url + 7, '/', w->url_size - 7);
  assert(hostname_end != NULL);
  char hostname[hostname_end - w->url - 7 + 1];
  memcpy(hostname, w->url + 7, hostname_end - w->url - 7);
  hostname[hostname_end - w->url - 7] = '\0';
  
  if (bl_check(hostname) == 1) {
    outstream_send(&w->outstream, strdup(DENY_RESPONSE), strlen(DENY_RESPONSE));
#ifdef PRINT_URLS
    printbuf("✘ %s\n", w->url, w->url_size);
#endif
    w->parser_dontpause = 1;
    return 0;
  }

  w->agent = NULL;
  struct http_agent *agent = get_agent(hostname, w);
  if (agent == NULL) {
    // invalid hostname or so
    outstream_send(&w->outstream, strdup(INVAL_RESPONSE), strlen(INVAL_RESPONSE));
#ifdef PRINT_URLS
    printbuf("  %s\n", w->url, w->url_size);
#endif
    w->parser_dontpause = 1;
    return 0;
  }
  
#ifdef PRINT_URLS
  printbuf("✔ %s\n", w->url, w->url_size);
#endif
  
  // FIXME alter content-encoding and stuff?
  
  // construct a buffer containing the entire header:
  // 1. find out how big it has to be
  int path_len = w->url_size - (hostname_end - w->url);
  size_t header_buffer_size = 0;
  header_buffer_size += strlen(http_method_strings[p->method]) + 1 + path_len + 1 + 8/* "HTTP/1.1" */ + 2; /* first line */
  {
    struct http_header *h = w->request_headers;
    struct http_header **origin = &w->request_headers;
    while (h != NULL) {
      printd("SAVED REQ HEADER: <<< %s: %s >>>\n", h->key, h->value);
      if (strcasecmp(h->key, "Connection") == 0 || strcasecmp(h->key, "Proxy-Connection") == 0) {
        free(h->key);
        free(h->value);
        *origin = h->next; // anchestry magic! my child shall be your child, my father,
        free(h);           // so that I can go in peace.
        h = *origin;
        continue;
      }
      header_buffer_size += strlen(h->key) + 2 + strlen(h->value) + 2;
      origin = &h->next;
      h = h->next;
    }
    
    headers_append_key(&w->request_headers, "Connection", 10);
    headers_append_value(&w->request_headers, "keep-alive", 10);
    header_buffer_size += 10+2+10+2;
  }
  header_buffer_size += 3; /* CR LF 0 */
  
  // 2. allocate and fill it
  char *header_buffer = safe_malloc(header_buffer_size);
  char *pos = header_buffer;
  BUF_APPEND_STR(pos, http_method_strings[p->method]);          // GET
  *(pos++) = ' ';                                               // <space>
  BUF_APPEND(pos, hostname_end, path_len);                      // /foo/bar?q=x
  BUF_APPEND_STR(pos, " HTTP/1.1\r\n");                         // <space> HTTP/1.1 \r\n
  {
    struct http_header *h = w->request_headers;
    while (h != NULL) {
      BUF_APPEND_STR(pos, h->key);
      BUF_APPEND_STR(pos, ": ");
      BUF_APPEND_STR(pos, h->value);
      BUF_APPEND_STR(pos, "\r\n");
      h = h->next;
    }
  }
  BUF_APPEND_STR(pos, "\r\n");
  *(pos++) = '\0';
  assert(pos - header_buffer == header_buffer_size);
  printd("HEADER READY FOR SENDING: \n<<<<<<<<<<<<<<<<<<<<\n%s\n>>>>>>>>>>>>>>>>>>>>\n", header_buffer);
  outstream_send(&agent->outstream, header_buffer, header_buffer_size - 1 /* the nullbyte is for debugging only, stupid! */);
  
  free_headers(&w->request_headers);
  
  return 0;
}

int on_client_body(http_parser *p, const char *data, size_t length) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  printbufd("on_client_body: %s\n", data, length);
  // FIXME
  return 0;
}

int on_client_message_complete(http_parser *p) {
  struct client_fd_watcher *w = CASTUP(p, struct client_fd_watcher, parser);
  printd("on_client_message_complete\n");
  assert(w->parser_paused == 0);
  if (w->parser_dontpause == 1) {
    // in case we synchronously rejected the request
    w->parser_dontpause = 0;
  } else {
    http_parser_pause(p, 1); // prevent pipelining from causing fuckups
    w->parser_paused = 1; // tell client_fd_data_cb() that this is not an error
  }
  return 0;
}

http_parser_settings client_settings = {
  .on_message_begin = on_client_message_begin,
  .on_url = on_client_url,
  .on_header_field = on_client_header_field,
  .on_header_value = on_client_header_value,
  .on_headers_complete = on_client_headers_complete,
  .on_body = on_client_body,
  .on_message_complete = on_client_message_complete
};

void process_client_data(struct client_fd_watcher *w, char *data, int read_data) {
  int nparsed = http_parser_execute(&w->parser, &client_settings, data, read_data);
  if (w->parser.upgrade) {
    // FIXME handle update
  } else if (nparsed != read_data && w->parser_paused == 0) {
      // FIXME handle error
  } else if (w->parser_paused == 1) {
    // If there's no associated agent, nobody can send data, and as we're about to make
    // sure that nobody can receive it either, this connection would be dead.
    assert(w->agent != NULL);
    
    // we're supposed to freeze the incoming data so that pipelining doesn't
    // cause large fuckups (e.g. mixing responses)
    alter_ev_io_events(&w->watcher, 0, EV_READ);
    
    // put the pending data into cyro
    w->pending_data_length = read_data - nparsed;
    w->pending_data = malloc(w->pending_data_length);
    memcpy(w->pending_data, data + nparsed, read_data - nparsed);
  }
}

void client_fd_data_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
  printd("client_fd_data_cb\n");
  struct client_fd_watcher *w = (struct client_fd_watcher *) watcher;
  assert(w->parser_paused == 0); // if the parser is paused, the IO watcher should be frozen
  char data[READ_CHUNK_SIZE];
  int read_data;
  while ((read_data = read(watcher->fd, data, READ_CHUNK_SIZE)) != -1) {
    if (read_data == 0) {
      kill_client(w);
      return;
    }
    process_client_data(w, data, read_data);
  }
  if (errno != EAGAIN) {
    // FIXME handle dropped connection!
  }
}

void client_outstream_error_cb(struct outstream *o) {
  struct client_fd_watcher *client = CASTUP(o, struct client_fd_watcher, outstream);
  kill_client(client);
}

// invoked by libev when listen_fd is ready
void new_tcp_clients_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
  int client_fd;
  while ((client_fd = accept(watcher->fd, NULL, 0)) != -1) {
    printd("new TCP client on socket %i\n", client_fd);
    unblock_fd(client_fd);
    
    struct client_fd_watcher *client_fd_watcher = malloc(sizeof(struct client_fd_watcher));
    client_fd_watcher->parser_paused = 0;
    client_fd_watcher->parser_dontpause = 0;
    client_fd_watcher->request_headers = NULL;
    client_fd_watcher->agent = NULL;
    client_fd_watcher->url = NULL;
    ev_io_init(&client_fd_watcher->watcher, client_fd_data_cb, client_fd, EV_READ);
    ev_io_start(loop, &client_fd_watcher->watcher);
    http_parser_init(&client_fd_watcher->parser, HTTP_REQUEST);
    outstream_init(&client_fd_watcher->outstream, client_fd, client_outstream_error_cb);
  }
  assert(errno == EAGAIN);
}

int main(int argc, char **argv) {
  // initialize libev
  struct ev_loop *loop = ev_default_loop(0);
  
  // prepare stuff
  struct sigaction action_ignore = {
    .sa_handler = SIG_IGN,
    .sa_mask = 0,
    .sa_flags = 0,
    .sa_restorer = NULL
  };
  sigaction(SIGPIPE, &action_ignore, NULL);
  idle_agents_by_host = ht_create();
  reload_domain_blacklist();
  
  // start listening
  int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
  unblock_fd(listen_fd);
  int on = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in6 listen_addr = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(8642),
    .sin6_flowinfo = 0,
    /*.sin6_addr*/
    .sin6_scope_id = 0
  };
  memset(&listen_addr.sin6_addr.s6_addr, 0, 15);
  listen_addr.sin6_addr.s6_addr[15] = 1;
  assert(bind(listen_fd, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_in6)) == 0);
  assert(listen(listen_fd, SOMAXCONN) == 0);
  struct listen_fd_watcher listen_fd_watcher;
  ev_io_init(&listen_fd_watcher.watcher, new_tcp_clients_cb, listen_fd, EV_READ);
  ev_io_start(loop, &listen_fd_watcher.watcher);
  
  // now enter the eventloop
  ev_loop(loop, 0);
  
  return 0;
}
