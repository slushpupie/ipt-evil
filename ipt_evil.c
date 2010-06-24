/*
 * Copyright 2010 Jay Kline <jay@slushpupie.com>
 *  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

 /* 
 * The ipt_evil command is an iptables userspace QUEUE table. It does "evil"
 * things to a tcp packet. At the moment, it only modifies the 64th byte to 
 * be a "!" but certainly could be easily modified to do other things to the
 * packet. 
 *
 * 
 * Example usage:
 * 
 *    # iptables -A INPUT -p tcp -p tcp --dport 7 \
 *          -m state --state ESTABLISHED,RELATED -j QUEUE
 *
 *    # ./ipt_evil
 *
 * Disclaimer:
 *
 * Do not use ipt_evil to do evil things.  Use ipt_evil to do good things, like
 * verify a protocol's integrity checking is working. Using ipt_evil to do 
 * evil things may result in hair loss, heart reversal, or navel discharge.
 * 
 */


#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libipq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 2048

struct ptcphdr
{
  __u32 src_addr;
  __u32 dst_addr;
  __u8 zero;
  __u8 proto;
  __u16 length;
};

static void
die (struct ipq_handle *h)
{
  ipq_perror ("passer");
  ipq_destroy_handle (h);
  exit (1);
}

uint16_t
in_csum (void *addr, int len)
{
  register int nleft = len;
  const uint16_t *w = addr;
  register uint16_t answer;
  register int sum = 0;

  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    sum += htons (*(u_char *) w << 8);

  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* truncate to 16 bits */
  return (answer);
}


uint16_t
tcp_csum (struct iphdr *iph, struct tcphdr *tcph)
{
  struct ptcphdr *ptcph;
  int totaltcp_len;
  unsigned char *packet;

  int tcpopt_len = tcph->doff * 4 - 20;
  int tcpdatalen = ntohs (iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);

  ptcph = malloc (sizeof (struct ptcphdr));
  ptcph->src_addr = iph->saddr;
  ptcph->dst_addr = iph->daddr;
  ptcph->zero = 0;
  ptcph->proto = IPPROTO_TCP;
  ptcph->length = htons (sizeof (struct tcphdr) + tcpopt_len + tcpdatalen);

  totaltcp_len =
    sizeof (struct ptcphdr) + sizeof (struct tcphdr) + tcpopt_len +
    tcpdatalen;
  packet = malloc (sizeof (unsigned char) * totaltcp_len);


  memcpy (packet, ptcph, sizeof (struct ptcphdr));
  memcpy (packet + sizeof (struct ptcphdr),
	  (unsigned char *) tcph, sizeof (struct tcphdr));
  memcpy (packet + sizeof (struct ptcphdr) +
	  sizeof (struct tcphdr),
	  (unsigned char *) iph + (iph->ihl * 4) + (sizeof (struct tcphdr)),
	  tcpopt_len);
  memcpy (packet + sizeof (struct ptcphdr) +
	  sizeof (struct tcphdr) + tcpopt_len,
	  (unsigned char *) tcph + (tcph->doff * 4), tcpdatalen);

  long chksm = in_csum (packet, totaltcp_len);
  free (packet);
  free (ptcph);
  return chksm;
}


int
main (int argc, char **argv)
{
  int status;
  unsigned char buf[BUFSIZE];
  struct ipq_handle *h;

  h = ipq_create_handle (0, PF_INET);
  if (!h)
    die (h);

  status = ipq_set_mode (h, IPQ_COPY_PACKET, BUFSIZE);
  if (status < 0)
    fprintf(stderr,"Did you forget to load the ip_queue module?\n");
    die (h);

  do
    {
      status = ipq_read (h, buf, BUFSIZE, 0);
      if (status < 0)
	die (h);

      switch (ipq_message_type (buf))
	{
	case NLMSG_ERROR:
	  fprintf (stderr, "Received error message %d\n",
		   ipq_get_msgerr (buf));
	  break;

	case IPQM_PACKET:
	  {
	    ipq_packet_msg_t *m;
	    struct iphdr *iph;
	    struct tcphdr *tcph;
	    m = ipq_get_packet (buf);
	    iph = ((struct iphdr *) m->payload);

	    fprintf (stderr, "Received packet (size: %d).\n", m->data_len);
	    if (iph->protocol != IPPROTO_TCP)
	      {
		status =
		  ipq_set_verdict (h, m->packet_id, NF_ACCEPT, 0, NULL);
		if (status < 0)
		  die (h);
		break;

	      }
	    tcph = (struct tcphdr *) (m->payload + (iph->ihl << 2));
	    if (m->data_len > 63)
	      {
                /* Do evil here. */
		m->payload[63] = 0x21;	/* "!" */

                /* Fix the TCP checksum */
		tcph->check = 0;
		tcph->check = tcp_csum (iph, tcph);

                /* Fix the IP checksum */
		iph->check = 0;
		iph->check = in_csum (iph, iph->ihl * 4);
	      }

	    status =
	      ipq_set_verdict (h, m->packet_id, NF_ACCEPT, m->data_len,
			       m->payload);
	    if (status < 0)
	      die (h);
	    break;
	  }

	default:
	  fprintf (stderr, "Unknown message type!\n");
	  break;
	}
    }
  while (1);

  ipq_destroy_handle (h);
  return 0;
}
