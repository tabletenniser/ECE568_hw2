#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

#include "common.h"

#define EXPECT_HOSTNAME "Alice's client"
#define EXPECT_EMAIL "ece568alice@ecf.utoronto.ca"
#define EXPECT_CA "ECE568 Certificate Authority"
#define PORT 8778

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error "
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_NO_VERIFY "ECE568-SERVER: Certificate does not verify\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

static int http_request(ssl, s, answer)
	SSL *ssl;
	int s;
	char *answer;
{
	int len, r;
	char buf[256];

	r = SSL_read(ssl, buf, 255);
	if (r < 0)
		berr_exit("SSL read\n");
	buf[255] = '\0';
	switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			len = r;
			break;
		case SSL_ERROR_ZERO_RETURN:
			goto shutdown;
		case SSL_ERROR_SYSCALL:
			fprintf(stderr, FMT_INCOMPLETE_CLOSE);
			goto done;
		default:
			berr_exit("SSL read problem");
	}

	printf(FMT_OUTPUT, buf, answer);
	len = strlen(answer)+1;		// For '\0' character
	r = SSL_write(ssl, answer, len);
	switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			if (len != r)
				err_exit("Incomplete write!");
			break;
		case SSL_ERROR_ZERO_RETURN:
			goto shutdown;
		case SSL_ERROR_SYSCALL:
			fprintf(stderr, FMT_INCOMPLETE_CLOSE);
			goto done;
		default:
			berr_exit("SSL write problem");
	}
shutdown:
	r=SSL_shutdown(ssl);
	if(r==0){		// SSL_shutdown fails because requiring a bidirectional shutdown.
		shutdown(s,1);
		r=SSL_shutdown(ssl);
	}
	switch(r){
		case 1:
			break; /* Success */
		case 0:
		case -1:
		default:
			printf("%d", r);
			berr_exit("Shutdown failed");
	}

done:
	SSL_free(ssl);
	return 0;
}

int check_cert(ssl,host,email)
	SSL *ssl;
	char *host;
	char *email;
{
	X509 *peer;
	char peer_CN[256];
	char peer_email[256];

	if(SSL_get_verify_result(ssl)!=X509_V_OK){
		berr_exit(FMT_NO_VERIFY);
	}

    // get and print CN, Email and CA
	peer=SSL_get_peer_certificate(ssl);
    if (peer == NULL){
        berr_exit(FMT_ACCEPT_ERR);
    }

	X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
	X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);

    printf(FMT_CLIENT_INFO, peer_CN, peer_email);

	return 1;
}


int main(int argc, char **argv)
{
	int s=0, sock, port=PORT;
	struct sockaddr_in sin;
	int val=1;
	pid_t pid;

	/*Parse command line arguments*/
	switch(argc){
		case 1:
			break;
		case 2:
			port=atoi(argv[1]);
			if (port<1||port>65535){
				fprintf(stderr,"invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s port\n", argv[0]);
			exit(0);
	}

	if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
		perror("socket");
		close(sock);
		exit(0);
	}

	memset(&sin,0,sizeof(sin));
	sin.sin_addr.s_addr=INADDR_ANY;
	sin.sin_family=AF_INET;		// for IP4
	sin.sin_port=htons(port);
	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));

	if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){	// bind a name to a socket (i.e sin to sock)
		perror("bind");
		close(sock);
		exit (0);
	}

	if(listen(sock,5)<0){		// listen on the socket, 5: max number of packets in the incoming queue
		perror("listen");
		close(sock);
		exit (0);
	}

    SSL_CTX *ctx = initialize_ctx("./bob.pem", "password", false);
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    SSL_CTX_set_cipher_list(ctx, "SHA1");		// TODO: check if SSLv2, SSLv3 and TLSv1 should be set here.

	while(1){
		if((s=accept(sock, NULL, 0))<0){
			perror("accept");
			close(sock);
			close(s);
			exit (0);
		}

		/*fork a child to handle the connection*/
		if((pid=fork())){
			close(s);
		}
		else {
			/*Child code*/
			BIO *sbio = BIO_new_socket(s, BIO_NOCLOSE);
			SSL *ssl = SSL_new(ctx);
			SSL_set_bio(ssl, sbio, sbio);
            SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

            // Check if the certificate exists AND CA is valid
			if (SSL_accept(ssl) <= 0){
				berr_exit(FMT_ACCEPT_ERR);
            }

			char *answer = "42";
			check_cert(ssl, EXPECT_HOSTNAME, EXPECT_EMAIL);
			/* Read the packet into buf using ssl, and write the answer back */
			http_request(ssl, s, answer);

			/* OLD COMMUNICATION CODE WITHOUT SSL */
			/* len = recv(s, &buf, 255, 0); */
			/* buf[len]= '\0'; */
			/* send(s, answer, strlen(answer), 0); */
			/* close(sock); */
			/* close(s); */
			return 0;
		}
	}

	close(sock);
	return 1;
}



