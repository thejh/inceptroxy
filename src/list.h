struct list_element {
  struct list_element *prev;
  struct list_element *next;
}

struct list {
  struct list_element *first;
  struct list_element *last;
}