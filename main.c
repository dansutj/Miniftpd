#include "sysutil.h"
#include "session.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "hash.h"

extern session_t* p_sess;
static unsigned int s_children;

static hash_t* s_ip_count_hash;
static hash_t* s_pid_ip_hash;

void handle_sigchld(int sig);
void check_limits(session_t* sess);
unsigned int hash_func(unsigned int buckets, void* key);
unsigned int handle_ip_count(void* ip);
void drop_ip_count(void* ip);


int main(void)
{
	parseconf_load_file(MINIFTP_CONF);	
	daemon(0, 0);

	if(getuid() != 0)
	{
		fprintf(stderr, "miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, handle_sigchld);
	
	session_t sess = 
	{
		//connection control
		0, -1, "", "", "",
		
		//data connection
		NULL, -1, -1, 0,		

		//limite transfer speed		
		0, 0, 0, 0,		

		//process communication
		-1, -1, 
		
		//is ascii
		0, 0, NULL, 0,

		//limit client
		0, 0
	};
	
	p_sess = &sess;
	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;

	s_ip_count_hash = hash_alloc(256, hash_func);
	s_pid_ip_hash = hash_alloc(256, hash_func);

	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
	struct sockaddr_in addr;
	int conn;
	pid_t pid;

	while(1)
	{
		conn = accept_timeout(listenfd, &addr, 0);
		if(conn == -1)
			ERR_EXIT("accept_timeout");

		unsigned int ip = addr.sin_addr.s_addr;
		sess.num_this_ip = handle_ip_count(&ip);		
	
		++s_children;	
		sess.num_clients = s_children;		
	
		pid = fork();
		if(pid == -1)
		{
			--s_children;
			ERR_EXIT("fork");
		}

		if(pid == 0)
		{
			close(listenfd);
			sess.ctrl_fd = conn;
			check_limits(&sess);
			signal(SIGCHLD, SIG_IGN);
			begin_session(&sess);
		}
		else
		{
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid),
				&ip, sizeof(ip)); 
			close(conn);
		}
	}
	return 0;
}


void check_limits(session_t* sess)
{
	if(tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many connected users, please try later.");
		exit(EXIT_FAILURE);
	}

	if(tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip)
	{
		ftp_reply(sess, FTP_IP_LIMIT, "There are too many connection from your internet address.");
		exit(EXIT_FAILURE);
	}
}


void handle_sigchld(int sig)
{
	pid_t pid;
	while((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		--s_children;
		unsigned int* ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));

		if(ip == NULL)
			continue; 

		drop_ip_count(ip);
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}
}


unsigned int hash_func(unsigned int buckets, void* key)
{
	unsigned int* number = (unsigned int*)key;
	return (*number) % buckets;
}


unsigned int handle_ip_count(void* ip)
{
	unsigned int count;
	unsigned int* p_count = (unsigned int*)hash_lookup_entry(s_ip_count_hash,
	ip, sizeof(unsigned int));	

	if(p_count == NULL)
	{
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int), 
			&count, sizeof(unsigned int));
	}
	else
	{
		count = *p_count;
		*p_count = ++count;
	}
	return count;
}


void drop_ip_count(void* ip)
{
	unsigned int count;
        unsigned int* p_count = (unsigned int*)hash_lookup_entry(s_ip_count_hash,
        ip, sizeof(unsigned int));

        if(p_count == NULL)
       		return;
      
        count = *p_count;
	if(count <= 0)
		return;
	
	*p_count = --count;
        if(count == 0)
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
}
