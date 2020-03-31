#define HAVE_REMOTE

#ifndef _XKEYCHECK_H
#define _XKEYCHECK_H
#endif
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <remote-ext.h>
#include <iostream>
#include <iomanip> 
#include <fstream>
#include <cstdio>
#include <time.h>
#include <cstdlib>
using namespace std;
#define threshold 1024*1024
/* IP֡��ʽ */
typedef struct ip_header {
	u_char ver_ihl;				//Version (4 bits) + Internet header length (4 bits)
	u_char tos;					//Type of service
	u_short tlen;				//Total length
	u_short identification;		//Identification
	u_short flags_fo;			//Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl;					//Time to live
	u_char proto;				//Protocol
	u_short crc;				//Header checksum
	u_char saddr[4];			//Source address
	u_char daddr[4];			//Destination address
	u_int op_pad;				//Option + Padding
} ip_header;

/* ��̫��������·��֡��ʽ */
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

FILE* file;//����ļ�csv

//typedef struct udp_header{
//    u_short sport;          // Դ�˿�(Source port)
//    u_short dport;          // Ŀ�Ķ˿�(Destination port)
//    u_short len;            // UDP���ݰ�����(Datagram length)
//    u_short crc;            // У���(Checksum)
//}udp_header;

/*
* �ûص������������ݰ�
* packet_handlerָ��һ�����Խ������ݰ��ĺ���
* ������������յ�ÿ���µ����ݰ����յ�һ��ͨ��״̬ʱ��libpcap������
*/
/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main() {
	file = fopen("output.csv", "w");
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;
	char packet_filter[] = "ip and udp";

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		//fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		cout << "Error in pcap_findalldevs: " << errbuf << "\n" << endl;
		system("pause");
		exit(1);
	}

	for (d = alldevs; d; d = d->next) {
		printf_s("%d. %s", ++i, d->name);
		if (d->description)
			printf_s(" (%s)\n", d->description);
		else
			printf_s(" (No description available)\n");
	}
	if (i == 0) {
		printf_s("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf_s("Enter the interface number (1-%d):", i);
	cin >> inum;

	if (inum < 1 || inum > i) {
		printf_s("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open(
		d->name,					//�豸��
		65536,						//�����,65536��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ
		1000,						//��ȡ��ʱʱ��
		NULL,						//Զ�̻�����֤
		errbuf						//���󻺳��
	)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap.\n", d->name);
		//cout << "Unable to open the adapter. " << d->name << " is not supported by WinPcap.\n" << endl;
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	/* Ԥ���� */
	//���������·��,ֻ������̫��
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		//fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		cout << "This program works only on Ethernet networks." << endl;
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	if (d->addresses != NULL)
		/* �����ӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ,����һ��C������� */
		netmask = 0xffffff;

	/* ��������ù����� */
	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		cout << "\nUnable to compile the packet filter.Check the syntax." << endl;
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}
	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		cout << "\nError setting the filter." << endl;
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	printf_s("\nListening on %s...\n", d->description);
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* ��ʼ���� */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	fclose(file);
	system("pause");
	return 0;

}

/* ͨ��libpcap��ÿһ����������ݰ����ûص����� */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	mac_header* mh;
	ip_header* ih;
	ofstream fout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	for (int i = 0; i < length; i++) {
		printf_s("%02X ", pkt_data[i]);		//���������������
		if ((i & 0xF) == 0xF)
			printf_s("\n");
	}

	printf_s("\n");

	/* �����Ĵ��� */
	mh = (mac_header*)pkt_data;			//ͨ��ǿ������ת��,������������ֵ���δ���ṹ����
	printf_s("mac_header:\n");
	printf_s("\tdest_addr: ");
	for(int i = 0; i < 6; i++){
		printf_s("%02X ", mh->dest_addr[i]);
	}
	printf_s("\n");
	printf_s("\tsrc_addr: ");
	for(int i = 0; i < 6; i++){
		printf_s("%02X ", mh->src_addr[i]);
	}
	printf_s("\n");
	printf_s("\ttype: %04X", ntohs((u_short)mh->type));
	printf_s("\n");

	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data + sizeof(mac_header));	//length of ethernet header
	//ͨ��ǿ������ת��,������������ֵ���δ���ṹ����

	printf_s("ip_header\n");
	printf_s("\t%-10s: %02X\n", "ver_ihl", ih->ver_ihl);
	printf_s("\t%-10s: %02X\n", "tos", ih->tos);
	printf_s("\t%-10s: %04X\n", "tlen", ntohs(ih->tlen));
	printf_s("\t%-10s: %04X\n", "identification", ntohs(ih->identification));
	printf_s("\t%-10s: %04X\n", "flags_fo", ih->flags_fo);
	printf_s("\t%-10s: %02X\n", "ttl", ih->ttl);
	printf_s("\t%-10s: %02X\n", "proto", ih->proto);
	printf_s("\t%-10s: %04X\n", "crc", ih->crc);
	printf_s("\t%-10s: %08X\n", "op_pad", ih->op_pad);
	printf_s("\t%-10s: ", "saddr");
	for(int i = 0; i < 4; i++){
		printf_s("%02X ",ih->saddr[i]);
	}
	printf_s(" ");
	for(int i = 0; i < 4; i++){
		printf_s("%d.",ih->saddr[i]);
	}
	printf_s("\n");
	printf_s("\t%-10s: ", "daddr");
	for(int i = 0; i < 4; i++){
		printf_s("%02X ",ih->daddr[i]);
	}
	printf_s(" ");
	for(int i = 0; i < 4; i++){
		printf_s("%d.",ih->daddr[i]);
	}
	printf_s("\n");
	printf_s("The length of the flame is %d\n", ntohs(ih->tlen) + 14);

	if (ntohs(ih->tlen) < threshold) {
		
		//ofstream file;
		//��Ҫ������ļ�
		//file.open("scoresheet.csv", ios::out | ios::trunc);
		time_t tt = time(NULL);//��䷵�ص�ֻ��һ��ʱ��cuo
		tm* t = localtime(&tt);
		//file << t->tm_year + 1900 << t->tm_mon + 1 << t->tm_mday << t->tm_hour << t->tm_min << t->tm_sec<<",";
		//file << mh->src_addr << "," << ih->saddr << "," << mh->dest_addr << "," << ih->daddr << "," << ntohs(ih->tlen)<<"," << ntohs(ih->tlen) + 14;
		fprintf_s(file, "%d-%d-%d %d:%d:%d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		for (int i = 0; i < 5; i++) {
			fprintf_s(file, "%02X-", mh->src_addr[i]);//ԴMAC��ַ
		}
		fprintf_s(file, "%02X,", mh->src_addr[5]);
		for (int i = 0; i < 3; i++) {
			fprintf_s(file, "%d.", ih->saddr[i]);//ԴIP��ַ
		}
		fprintf_s(file, "%d,", ih->saddr[3]);
		for (int i = 0; i < 5; i++) {
			fprintf_s(file, "%02X-", mh->dest_addr[i]);//Ŀ��MAC��ַ
		}
		fprintf_s(file, "%02X,", mh->dest_addr[5]);
		for (int i = 0; i < 3; i++) {
			fprintf_s(file, "%d.", ih->daddr[i]);//Ŀ��IP��ַ
		}
		fprintf_s(file, "%d,", ih->daddr[3]);
		fprintf_s(file, "%d", ntohs(ih->tlen));
		fprintf_s(file, "\n");
		
	}
	else {
		time_t tt = time(NULL);//��䷵�ص�ֻ��һ��ʱ��cuo
		tm* t = localtime(&tt);
		printf_s("[%d-%d-%d %d:%d:%d]", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		printf_s("[");
		for (int i = 0; i < 5; i++) {
			printf_s("%02X-", mh->src_addr[i]);
		}
		printf_s("%02X,", mh->src_addr[5]);
		for (int i = 0; i < 3; i++) {
			printf_s("%02X.", ih->saddr[i]);
		}
		printf_s("%02X", ih->saddr[3]);
		printf_s("] SNED");
		printf_s("%d", ntohs(ih->tlen));
		printf_s("bytes out of limit.");

		printf_s("[%d-%d-%d %d:%d:%d]", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		printf_s("[");
		for (int i = 0; i < 5; i++) {
			printf_s("%02X-", mh->dest_addr[i]);
		}
		printf_s("%02X,", mh->dest_addr[5]);
		for (int i = 0; i < 3; i++) {
			printf_s("%02X.", ih->daddr[i]);
		}
		printf_s("%02X,", ih->daddr[3]);
		printf_s("] RECV");
		printf_s("%d", ntohs(ih->tlen));
		printf_s("bytes out of limit.");
	}
}