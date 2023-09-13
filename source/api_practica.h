
#include "lwip/opt.h"

#include "lwip/arch.h"
#include "lwip/netbuf.h"
#include "lwip/sys.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/api.h"

err_t verif_crc(uint8_t *dato, size_t len);

uint8_t practica_dec(uint8_t *body, size_t len_body);

uint8_t practica_enc(uint8_t *mess, size_t len_mess);

uint8_t practica_crear_crc(uint8_t *messag, size_t len);

err_t practica_read(struct netconn *conn, char *buf);

err_t practica_write(struct netconn *conn, char *message, size_t *lent);


