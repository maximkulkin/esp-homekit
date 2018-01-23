/*
adapted from https://gist.github.com/Groxx/310147
*/

typedef void * queue_data_type;
struct queue_item {
	queue_data_type contents;
	struct queue_item* next;
};
struct queue_root {
	struct queue_item* head;
	struct queue_item* tail;
};

typedef struct queue_root* QueueHandle_t;

QueueHandle_t xQueueCreate(int size, int datasize) {
    QueueHandle_t queue = malloc(sizeof(struct queue_root));
	queue->head = queue->tail = NULL;
    return queue;
}

void vQueueDelete(QueueHandle_t t) {
    free(t);
}

void xQueueSendToBack(struct queue_root* queue, queue_data_type *contents, int _) {
	struct queue_item *item = malloc(sizeof(item));
	item->contents = *contents;
	item->next = NULL;
	if (queue->head == NULL){
		queue->head = queue->tail = item;
	} else {
		queue->tail = queue->tail->next = item;
	}
}

int xQueueReceive(struct queue_root* queue, queue_data_type *popped, int _) {
	if (queue->head == NULL){
		return 0;
    }
    *popped = queue->head->contents;
    struct queue_item* next = queue->head->next;
    free(queue->head);
    queue->head = next;
    if (queue->head == NULL)
        queue->tail = NULL;
	return 1;
}
