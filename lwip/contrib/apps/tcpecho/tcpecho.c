/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "tcpecho.h"

#include "lwip/opt.h"

#if LWIP_NETCONN

#include "lwip/sys.h"
#include "lwip/api.h"
#include "api_practica.h"
/*-----------------------------------------------------------------------------------*/
static void
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  void *data;
  u16_t len;
  LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 7);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  PRINTF("New connection created \r\n");
  netconn_bind(conn, IP_ADDR_ANY, 7);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */
  netconn_listen(conn);


  while (1) {
	  /* Grab new connection. */
	  err = netconn_accept(conn, &newconn);
	  /* Process the new connection. */
	  PRINTF("New connection accepted %p\r\n", newconn);
	  size_t tam;
	  if (err == ERR_OK) {
		  do {
			  char buf[128]="";
			  PRINTF("Ready to read \r\n");
			  PRINTF("\r\n");
			  if ((err =  practica_read(newconn, &buf)) == ERR_OK) {
				  PRINTF("Dato listo para empezar fase de envio \r\n");
				  PRINTF("\r\n");
				  tam = strlen(&buf);
				  err = practica_write(newconn, buf, tam);
				  if (err == ERR_OK) {
				  PRINTF("Message received succesfully \r\n");
				  PRINTF("\r\n");
				  PRINTF("\r\n");
				  PRINTF("\r\n");
				  }
				  if (err != ERR_OK) {
					  PRINTF("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
				  }
				  /* Delete data buf */

			  }

		  } while (err == ERR_OK);
	  }
	  /* Close connection and discard connection identifier. */
	  PRINTF("Close and delete connection \r\n");
	  netconn_close(newconn);
	  netconn_delete(newconn);
    }

}
/*-----------------------------------------------------------------------------------*/
void
tcpecho_init(void)
{
  sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
/*-----------------------------------------------------------------------------------*/

#endif /* LWIP_NETCONN */
