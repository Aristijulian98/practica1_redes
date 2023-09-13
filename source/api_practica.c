
/*
 * This is an API to implement an encryption an integrity layer to include in
 * the TCP echo example.
 */

#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "fsl_crc.h"

#include "tcpecho.h"
#include "lwip/api.h"

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/netbuf.h"

/* Function to initialize CRC32 */
static void InitCrc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

/* Function to check CRC32 */
err_t verif_crc(uint8_t *dato, size_t len)
{
	/* Initialize valors */
	err_t err;
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	uint8_t data_8[128];
	uint8_t crc_calc[128];
	uint8_t crc_recv[128];
	uint8_t crc_rev[128];

	InitCrc32(base, 0xFFFFFFFFU);
	memcpy(data_8, dato, len);

	/* Obtain body of message */
	for(int i=0; i<(len - 4); i++) {
		crc_calc[i] = data_8[i];
	}

	/* Obtain CRC of message */
	for(int i=0; i <= 4; i++) {
		crc_recv[i] = data_8[i + (len - 4)];
	}

	/* Convert since uint8_t from uint32_t */
	uint32_t recv_crc = 0;
	memcpy(&recv_crc, crc_recv, 4);

	/* Calculate CRC */
	CRC_WriteData(base, (uint8_t *)&crc_calc[0], (len - 4));
	checksum32 = CRC_Get32bitResult(base);

    /* Print results */
	PRINTF("El CRC calculado es : %u\r\n", checksum32);
	PRINTF("El CRC recibido es : %u\r\n", recv_crc);

	/* Compare calculated VS received */
	if (checksum32 == recv_crc)
	{
		err = ERR_OK;
		PRINTF("...Check Success. CRC calculated and receiver are equals \r\n");
		PRINTF("\r\n");
	}
	else {
		err = ERR_ARG;
		PRINTF("...Check fail. CRC expected: %u\r\n", checksum32);
		PRINTF("\r\n");
	}
	return err;
}

/* Function to decrypt message */
uint8_t practica_dec(uint8_t *body, size_t len_body)
{
	uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct AES_ctx ctx;
	uint8_t body_dec[128];

	/* Initialize AES */
	AES_init_ctx_iv(&ctx, key, iv);

	/* Decrypt message */
	AES_CBC_decrypt_buffer(&ctx, body, len_body);

	return *body;
}

/* Function to encrypt */
uint8_t practica_enc(uint8_t *mess, size_t len_mess)
{
	uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct AES_ctx ctx;

	/* Initialize AES */
	AES_init_ctx_iv(&ctx, key, iv);

	/* Encrypt message */
	AES_CBC_encrypt_buffer(&ctx, mess, len_mess);

	return *mess;

}

/* Function to create CRC32 */
uint8_t practica_crear_crc(uint8_t *messag, size_t len)
{
	/* Initialize valors */
	err_t err;
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	uint32_t checksum[128];
	uint8_t crc[128];
	uint8_t *crc_char;
	uint8_t *data_crc[128];

	/* Calculate CRC32 */
	InitCrc32(base, 0xFFFFFFFFU);
	CRC_WriteData(base, (uint8_t *)&messag[0], len);
	checksum32 = CRC_Get32bitResult(base);

	PRINTF("CRC-32: %u\r\n", checksum32);
	memcpy(checksum, &checksum32, 4);
	memcpy(crc, &checksum32, 4);

	/* Add CRC32 on message */
	crc_char = (char *)&checksum32;
	for(int i=0;i<4;i++){
		messag[len + i] = crc_char[i];
	}

	return *messag;
}

/* Function to receive message */
err_t practica_read(struct netconn *conn, char *buf)
{
	/* Initialize valors */
	err_t err;
	void *data;
	u16_t len;
	struct netbuf *new_buf;
	uint8_t dato[128];
	uint8_t body_msg[128];
	uint8_t mensaje;
	uint8_t lenth;
	uint8_t message[128];
	size_t lent;

	/* Receive data from client */
	err = netconn_recv(conn, &new_buf);
	netbuf_data(new_buf, &data, &len);
	if(err == ERR_OK){
		memcpy(dato, data, len);
		PRINTF("El dato encriptado y con CRC es: ");
		for(int i=0; i<len; i++) {
			PRINTF("0x%02x,", dato[i]);
		}
		PRINTF("\r\n");
		PRINTF("\r\n");

	/* Check CRC32 */
		err = verif_crc(dato, len);
		if(err==ERR_OK){

	/* Obtain body message with padding for decrypt */
			for(int i=0; i<(len - 4); i++) {
				body_msg[i] = dato[i];
			}

	/* Decrypt message */
			mensaje = practica_dec(body_msg, (len - 4));
			memcpy(message, &mensaje, len - 4);
			for(int i=0; i<len - 4; i++) {
				message[i] = message[i+1];
			}
			lent = strlen(message);
			memcpy(buf, message, lent);
			PRINTF("Mensaje decriptado y verifcado: %s\r\n", buf);
			PRINTF("\r\n");
			PRINTF("\r\n");
		}
	}
	return err;
}

/* Function to send message */
err_t practica_write(struct netconn *conn, char *message, size_t *lent)
{
	/* Initialize valors */
	err_t err;
	err = ERR_OK;
	u16_t len = strlen(message);
	uint8_t data_send[128] = "";
	size_t data_len, data_padded_len;
	uint8_t mes_pad[128] = {0};
	uint8_t mens_enc;
	uint8_t mens_enc_crc;
	uint8_t enc_crc;
	uint8_t mens_enc_a[128] = {0};
	uint8_t enc_crc_a[128];

	memcpy(data_send, message, lent);

	/* Add padding in data */
	data_len = strlen(data_send);
	data_padded_len = data_len + (16 - (data_len%16) );
	memcpy(mes_pad, data_send, data_len);

	/* Encrypt message */
	mens_enc = practica_enc(mes_pad, data_padded_len);
	memcpy(mens_enc_a, &mens_enc, data_padded_len + 1);
	for(int i=0; i<data_padded_len + 1; i++) {
		mens_enc_a[i] = mens_enc_a[i+1];
	}
	memcpy(&mens_enc_crc, mens_enc_a, data_padded_len + 1);

	/* Generate CRC32 */
	enc_crc = practica_crear_crc(&mens_enc_crc, data_padded_len);
	memcpy(enc_crc_a, &enc_crc, data_padded_len + 5);
	for(int i=0; i<data_padded_len + 5; i++) {
		enc_crc_a[i] = enc_crc_a[i+1];
	}

	/* Send encrypted message to client */
	err = netconn_write(conn, enc_crc_a, (data_padded_len + 4), NETCONN_COPY);
	PRINTF("Message sent to client: ");
	for(int i=0; i<data_padded_len + 4; i++) {
		PRINTF("0x%02x,", enc_crc_a[i]);
	}
	PRINTF("\r\n");
	PRINTF("\r\n");
	return err;
}
