#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "common.h"

#define HOST "localhost"
#define EXPECT_HOSTNAME "Bob's Server"
#define EXPECT_EMAIL "ece568bob@ecf.utoronto.ca"
#define PORT 8778

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

int check_cert(ssl,host,email)
	SSL *ssl;
	char *host;
	char *email;
{
	X509 *peer;
	char peer_CN[256];
	char peer_email[256];

	if(SSL_get_verify_result(ssl)!=X509_V_OK){
		printf("SSL_get_verify_result(ssl): %ld", SSL_get_verify_result(ssl));
		berr_exit(FMT_NO_VERIFY);
	}

	/*Check the cert chain. The chain length
	 *       is automatically checked by OpenSSL when
	 *             we set the verify depth in the ctx */

	/*Check the common name*/
	peer=SSL_get_peer_certificate(ssl);
	X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
	if(strcasecmp(peer_CN,host)){
		printf("Expect name: %s; Got name: %s.", host, peer_CN);
		err_exit(FMT_CN_MISMATCH);
	}

	X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);
	if(strcasecmp(peer_email, email)){
		printf("Expect email: %s; Got email: %s.", email, peer_email);
		err_exit(FMT_EMAIL_MISMATCH);
	}
	return 1;
}

static int http_request(ssl)
	SSL *ssl;
{
	return(0);
}

int main(int argc, char **argv)
{
	int sock, port=PORT;
	char *host=HOST;
	struct sockaddr_in addr;
	struct hostent *host_entry;
	char buf[256];
	char *secret = "What's the question?";

	/*Parse command line arguments*/
	switch(argc){
		case 1:
			break;
		case 3:
			host = argv[1];
			port=atoi(argv[2]);
			if (port<1||port>65535){
				fprintf(stderr,"invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s server port\n", argv[0]);
			exit(0);
	}

	/*get ip address of the host*/

	host_entry = gethostbyname(host);

	if (!host_entry){
		fprintf(stderr,"Couldn't resolve host");
		exit(0);
	}

	memset(&addr,0,sizeof(addr));
	addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);
	printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

	/*open socket*/
	if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
		perror("socket");
	if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
		perror("connect");

	/* IN-SECURE COMMUNICATION. */
	/* send(sock, secret, strlen(secret),0); */
	/* len = recv(sock, &buf, 255, 0); */
	/* buf[len]='\0'; */

	/* SECURE COMMUNICATION. */
	SSL_CTX *ctx = initialize_ctx("./alice.pem", "password");
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);		// only enable SSLv3 and TLSv1
	SSL_CTX_set_cipher_list(ctx, "SHA1");		// TODO: check if SSLv3, SSLv2 and TLSv1 should be set here.
	/* Connect the SSL socket */
	SSL *ssl = SSL_new(ctx);
	BIO *sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	puts("Before SSL_connect(ssl)");
	if(SSL_connect(ssl)<=0)
		berr_exit(FMT_CONNECT_ERR);
	puts("SSL_connect(ssl) finished!");

	if(check_cert(ssl, EXPECT_HOSTNAME, EXPECT_EMAIL)){
		puts("check_cert(ssl, host, email) finished!");
		http_request(ssl);
		puts("http_request(ssl) finished!");
	}

	/* this is how you output something for the marker to pick up */
	printf(FMT_OUTPUT, secret, buf);

	destroy_ctx(ctx);
	close(sock);
	return 1;
}
