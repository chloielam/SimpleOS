#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */	
	int currentPosition = q->size;
	if (q->size == 0)
	{
		q->proc[0] = proc;
		q->size ++;
	}
	else{ //Queue order: from smallest number -> largest number
		  // ">=" for FCFS (proc before will be pushed to the rear to be executed earlier)
		while(currentPosition > 0 && 
			  proc->priority < q->proc[currentPosition - 1]->priority ) 
		{
			q->proc[currentPosition] = q->proc[currentPosition - 1];
			currentPosition --;
		}
		q->proc[currentPosition] = proc;
		q->size ++;
	}  
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	struct pcb_t* process;
	if(empty(&q))
	{
		return NULL;
	}
	else{
		process = q->proc[q->size-1];
		q->size --;
	}
	return process;
}

