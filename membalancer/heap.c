/* Copyright (c) 2021, AMD
 *
 * Min and Max heap functionality
 */
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>

struct heap_elem {
	void *elem;
};

struct heap {
	int max_elements;
	int size;
	int (*compare)(void *a, void *b);
	struct heap_elem *elem;
};

int heap_create(int elements,
		int (*compare)(void *a, void *b),
		struct heap **heapout)
{
	struct heap *heap;

	heap = malloc(sizeof(*heap));
	if (!heap)
		return -ENOMEM;

	heap->max_elements = elements;
	heap->size         = 0;
	heap->compare      = compare;
	heap->elem         = malloc(sizeof(heap->elem) * elements);
	if (!heap->elem) {
		free(heap);
		return -ENOMEM;
	}

	*heapout = heap;
	
	return 0;
}

void heap_destroy(struct heap *heap)
{
	int i;
	
	for (i=0; i < heap->size; i++)
		free(heap->elem[i].elem);

	free(heap->elem);
	free(heap);
}

static void heap_expand(struct heap *heap)
{
	void *ptr;

	ptr = realloc(heap->elem, sizeof(heap->elem) * 2 * heap->max_elements);
	if (!ptr)
		return;

	heap->elem = ptr;
	heap->max_elements *= 2;
}

static int compare(struct heap *heap, struct heap_elem *first,
		   struct heap_elem *second)
{
	return heap->compare(first, second);
}

static void heapify_bottom_to_top(struct heap *heap)
{
	int idx, parent;
	struct heap_elem *tmp;

	idx = heap->size - 1;

	while (idx > 0) {
		parent = idx / 2;
		if (compare(heap, heap->elem[parent].elem,
			    heap->elem[idx].elem)) {
			tmp = heap->elem[idx].elem;
			heap->elem[idx].elem = heap->elem[parent].elem;
			heap->elem[parent].elem = tmp;
		}
		idx = parent;
	}
}
	
static void heapify_top_to_bottom(struct heap *heap)
{
	int idx, l, r, swp;
	struct heap_elem *tmp;

	idx = 0;
	while (idx < heap->size) {
		l = 2 * idx + 1;
		r = l + 1;

		swp = idx;
		
		if (l < heap->size && compare(heap, heap->elem[swp].elem,
			   heap->elem[l].elem))
			swp = l;

		if (r < heap->size && compare(heap, heap->elem[swp].elem,
			   heap->elem[r].elem))
			swp = r;

		if (swp == idx)
			break;

		tmp = heap->elem[swp].elem;
		heap->elem[swp].elem = heap->elem[idx].elem;
		heap->elem[idx].elem = tmp;
		idx = swp;
	}
}

int heap_insert(struct heap *heap, void *elem)
{
	if (heap->size >= heap->max_elements) {
		heap_expand(heap);
		if (heap->size >= heap->max_elements)
			return -ENOMEM;
	}

	heap->elem[heap->size++].elem = elem;
	heapify_bottom_to_top(heap);

	return 0;
}

int heap_remove(struct heap *heap, void **elemout, int *cookie)
{
	if (heap->size < 1)
		return -ENOENT;
	
	*elemout = heap->elem[0].elem;
	heap->elem[0].elem = heap->elem[--heap->size].elem;
	heap->elem[heap->size].elem = NULL; /* leak */
	
	if (heap->size <= 1)
		return 0;

	heapify_top_to_bottom(heap);

	return 0;
}

#if 0
int mycomp(void  *a, void *b)
{
	if (*(int *)a > *(int *)b) 
		return 1;

	return 0;
}

int main(void)
{
	struct heap *heap;
	int a[] = {5, 4, 8, 9, 2, 99, 1, 6, -1, 0, 88, 999, -233};
	int i;

	if (heap_create(100, mycomp, &heap)) {
		printf("Cannot create heap ...\n");
		return -1;

	}

	for (i=0; i < sizeof(a)/sizeof(int); i++)
		heap_insert(heap, &a[i]);

	printf("\n");
		
	while (heap->size) {
		void *elem;

		if (heap_remove(heap, &elem))
			break;
	}

	return 0;
}
#endif
