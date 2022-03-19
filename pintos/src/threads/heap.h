#ifndef THREADS_HEAP_H
#define THREADS_HEAP_H

/* A heap is a container that provides constant time lookup of the largest
    element, at the expense of logarithmic insertion and extraction. */

#include <stdbool.h>
#include <stddef.h>

/* Max heap size. */
#define MAX_SIZE 1024

/* Compares the value of two heap elements A and B.
    Returns true if A is less than B, or
    false if A is greater than or equal to B. */
typedef bool heap_less_func(void *a, void *b);  //为复杂的声明定义一个别名

/* Pointer to heap element. */
typedef void *heap_elem;       //一个别名 void *类型  无类型指针 void *可以指向任何类型的数据 为heap_elem

/* Heap. */
struct heap
{
    heap_elem c[MAX_SIZE]; /* Container. */  
    size_t size;           /* Size. */
    heap_less_func *cmp;   /* Compare function. */  //函数指针  返回bool型，拥有参数void *a, void *b
    bool max_heap;         /* true for a max-heap, false for a min-heap. */
};

void heap_init(struct heap *, heap_less_func, bool max_heap);
heap_elem heap_top(struct heap *);
bool heap_empty(struct heap *);
void heap_push(struct heap *, heap_elem);
heap_elem heap_pop(struct heap *);

#endif /* threads/heap.h */
