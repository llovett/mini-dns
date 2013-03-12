#ifndef linkedlist_h
#define linkedlist_h

typedef struct ll_node {
    char *server;
    char *server_addr;
    struct ll_node *next;
} linkedlist;

linkedlist *list_new(char *servername) {
    linkedlist *node = (linkedlist*)malloc(sizeof(linkedlist));
    node->server = strdup(servername);
    node->server_addr = NULL;
    node->next = NULL;
    return node;
}

#endif

