#include <stdio.h>
#include <unistd.h>
#include <rte_memory.h>
#include <rte_ring.h>
#include <rte_mempool.h>

#define RING_SIZE			64
static const char *_MSG_POOL = "MSG_POOL";
struct rte_mempool *message_pool;
struct lcore_params {
	struct rte_ring *send_ring, *recv_ring;
};

struct data {
	uint32_t value;
};
struct private_data {
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
        struct private_data * priv = (struct private_data *)rte_mempool_get_priv(message_pool);
	printf("core %u: Received %d and private data %u\n", lcore_id, d->value, priv->value);
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
        void *p  = NULL;
        if (rte_mempool_get(message_pool, &p) < 0)
                rte_panic("Failed to get message buffer\n");
        struct data * msg = (struct data *)p;
        msg->value = values[i];
        if (rte_ring_enqueue(ring, msg) < 0) {
                printf("Failed to send message - message discarded\n");
                rte_mempool_put(message_pool, p);
        }
    }
    struct private_data * priv = (struct private_data *)rte_mempool_get_priv(message_pool);
    priv->value =1000;

}



static void
print_ring(struct rte_ring * ring)
{
	struct data * d;
	while (rte_ring_dequeue(ring, (void *)&d) == 0) {
		printf("DEQ-DATA:%d\n", d->value);
		//free(d);
	}
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
        //const unsigned pool_size = sizeof(struct data) * 4;
        const unsigned pool_size = 64;
        const unsigned pool_cache = 32;
        const unsigned priv_data_sz = sizeof(struct private_data);
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

        message_pool = rte_mempool_create(_MSG_POOL, pool_size,
                                sizeof(struct data), pool_cache, priv_data_sz,
                                NULL, NULL, NULL, NULL,
                                rte_socket_id(), 0);
         if (message_pool == NULL)
                rte_exit(EXIT_FAILURE, "Problem getting message pool\n");
	enqueue_sample_data(params.send_ring);


	printf("Starting lcores.\n");
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch((lcore_function_t*)lcore_recv, &params, lcore_id);
	}

	printf("Waiting for lcores to finish.\n");
	rte_eal_mp_wait_lcore();

	print_ring(params.recv_ring);
        getchar();
	return 0;
}
