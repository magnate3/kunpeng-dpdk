#include <stdio.h>
#include <unistd.h>
#include <rte_memory.h>
#include <rte_ring.h>

#define RING_SIZE			64

struct lcore_params {
	struct rte_ring *send_ring, *recv_ring;
};

struct data {
	uint32_t value;
};

static int
lcore_recv(struct lcore_params *p)
{
	unsigned lcore_id = rte_lcore_id();
	printf("Starting core %u\n", lcore_id);
	void * vp;
	while (rte_ring_dequeue(p->send_ring, &vp) != 0){
		usleep(5);
	}
	struct data * d = (struct data *) vp;
	printf("core %u: Received %d\n", lcore_id, d->value);
	d->value ++;
	rte_ring_enqueue(p->recv_ring, (void *)d);

	return 0;
}

static void
enqueue_sample_data(struct rte_ring * ring)
{
	int i;
	uint32_t values[4] = {1, 3, 5, 8};

	for (i = 0; i < 4; ++i) {
		struct data * d = malloc(sizeof(struct data));
		d->value = values[i];
		rte_ring_enqueue(ring, (void*)d);
	}
}

static void
print_ring(struct rte_ring * ring)
{
	struct data * d;
	while (rte_ring_dequeue(ring, (void *)&d) == 0) {
		printf("DEQ-DATA:%d\n", d->value);
		free(d);
	}
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

	struct lcore_params params;

	params.send_ring = rte_ring_create("R1", RING_SIZE, SOCKET_ID_ANY, 0/*RING_F_SP_ENQ*/);
	if (!params.send_ring) {
		rte_exit(EXIT_FAILURE, "Problem getting sending ring\n");
	}

	params.recv_ring = rte_ring_create("R2", RING_SIZE, SOCKET_ID_ANY, 0/*RING_F_SC_DEQ*/);
	if (!params.recv_ring) {
		rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");
	}

	enqueue_sample_data(params.send_ring);


	printf("Starting lcores.\n");
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch((lcore_function_t*)lcore_recv, &params, lcore_id);
	}

	printf("Waiting for lcores to finish.\n");
	rte_eal_mp_wait_lcore();

	print_ring(params.recv_ring);

	return 0;
}
