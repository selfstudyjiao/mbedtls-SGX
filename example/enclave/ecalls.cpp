#include "Enclave_t.h"
#include "enc.h"
#include "s_server.h"
#include "Log.h"
#include "ssl_conn_hdlr.h"

#ifdef __cplusplus
extern "C" {
#endif

uint64_t p_sgx_connect = uint64_t(&sgx_connect);

int sgx_connect();
int sgx_accept();
void ssl_conn_init();
void ssl_conn_teardown();
void ssl_conn_handle(long int thread_id, thread_info_t *thread_info);
void ecall_output_func_addr(uint64_t *sgx_connect_addr);

#ifdef __cplusplus
}
#endif

int sgx_connect()
{
    client_opt_t opt;
    unsigned char buf[1024];
    client_opt_init(&opt);
    opt.debug_level = 1;
    opt.server_name = "www.google.com";
    opt.server_port = "443";

    return ssl_client(opt, NULL, 0, buf, sizeof buf);
}

int sgx_accept()
{
    return ssl_server();
}

TLSConnectionHandler* connectionHandler;

void ssl_conn_init(void) {
  connectionHandler = new TLSConnectionHandler();
}

void ssl_conn_handle(long int thread_id, thread_info_t* thread_info) {
  int (*test_func)(void);
  test_func = (int (*)())thread_info->config;
  (*test_func)();
  connectionHandler->handle(thread_id, thread_info);
}

void ssl_conn_teardown(void) {
  delete connectionHandler;
}

void ecall_output_func_addr(uint64_t *sgx_connect_addr)
{
    *sgx_connect_addr = p_sgx_connect;
}
