/* 
    ********************************************************************
    Odsek:          Elektrotehnika i racunarstvo
    Departman:      Racunarstvo i automatika
    Katedra:        Racunarska tehnika i racunarske komunikacije (RT-RK)
    Predmet:        MRKiRM1
    Godina studija: IV
    Skolska godina: 2018/2019
    Semestar:       Letnji (VIII)
    
    Ime fajla:      encryption.cpp
    ********************************************************************
*/

// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"
#define ROW 3;
#define COL 7;

// Function declarations
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);	// Callback function invoked by WinPcap for every incoming packet
unsigned char* encrypt_data(const unsigned char* packet_data, unsigned char* app_data, int app_length);					// Returns a copy of packet with encrypted application data
void print_message_as_table(unsigned char* data, int rows_max, int columns_max);										// Prints application data using table format
int find_key(int key, int * keys, int keys_size);																		// Finds specific key in array of keys and returns its index

#define ETHERNET_FRAME_MAX 1518		// Maximal length of ethernet frame

// Main function captures packets from the file
int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	
	// Open the capture file 
	if ((device_handle = pcap_open_offline("original_packets.pcap", // Name of the device
								error_buffer	  // Error buffer
							)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}

	// Open the dump file 
	pcap_dumper_t* file_dumper = pcap_dump_open(device_handle, "encrypted_packets.pcap");
	

	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	struct bpf_program fcode;

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, "ip and udp", 1, 0xffffff) < 0)
	{
		 printf("\n Unable to compile the packet filter. Check the syntax.\n");
		 return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	// Read and dispatch packets until EOF is reached
	pcap_loop(device_handle, 0, packet_handler, (unsigned char*) file_dumper);

	// Close the file associated with device_handle and deallocates resources
	pcap_close(device_handle);

	return 0;
}

// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char* file_dumper, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	/* DATA LINK LAYER - Ethernet */

	// Retrive the position of the ethernet header
	ethernet_header * eh = (ethernet_header *)packet_data;
	
	/* NETWORK LAYER - IPv4 */

	// Retrieve the position of the ip header
	ip_header* ih = (ip_header*) (packet_data + sizeof(ethernet_header));
	
	// TRANSPORT LAYER - UDP
	if(ih->next_protocol != 17)
	{
		return;
	}
	
	// Retrieve the position of udp header
	udp_header* uh = (udp_header*) ((unsigned char*)ih + ih->header_length * 4);

	// Retrieve the position of application data
	unsigned char* app_data = (unsigned char *)uh + sizeof(udp_header);

	// Total length of application data
	int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

	// Encrypt data using tranposition of rows and columns
	unsigned char * encrypted_packet = encrypt_data(packet_data, app_data, app_length);

	// Dump encrypted packets
	pcap_dump((unsigned char*) file_dumper, packet_header, encrypted_packet);
}

// Returns a copy of packet with encrypted application data
unsigned char* encrypt_data(const unsigned char* packet_data, unsigned char* app_data, int app_length)
{

	// Reserve memory for copy of the packet
	
	int i = 0;
	int j = 0;
	int n = 0;

	// TODO 1: Define keys
	unsigned char encrypted_packet[ETHERNET_FRAME_MAX];
	unsigned char encrypted_packetcpy[ETHERNET_FRAME_MAX];
	unsigned char encrypted[3][7];
	unsigned int transRow[3] = {1, 0, 2};
	unsigned int transCol[7] = {1, 0, 6, 2, 4, 3, 5};
	int app_position;
	unsigned char *enc_msg;

	// TODO 2: Print original message in table format
	print_message_as_table(app_data, 3, 7);
	// TODO 3: Create a copy of the packets (copy headers and initialize application data with zeros)
	app_position = app_data - packet_data;

	enc_msg = encrypted_packet + app_position;

	memcpy(encrypted_packet, packet_data, app_position);

	memset(encrypted_packet, '0', app_length);

	printf("\n");

	print_message_as_table(encrypted_packet, 3, 7);

	printf("\n");


	// TODO 4: Find new row and column indices using old row and column indices
	for(i = 0; i < 3; i++)
	{
		n = transRow[i];
		for(j = 0; j < 7; j++)
		{
			encrypted_packet[i*7 + j] = app_data[n*7 + j];
		}
	}

	memcpy(encrypted_packetcpy, encrypted_packet,  app_length);

	for(i = 0; i < 7; i++)
	{
		n = transCol[i];
		for(j = 0; j < 3; j++)
		{
			encrypted_packet[j*7 + i] = encrypted_packetcpy[j*7 + n];
		}
	}

	


	// TODO 5: Encrypt application data

	// TODO 6: Print encrypted message

	printf("\n");

	print_message_as_table(encrypted_packet, 3, 7);

	printf("\n");

	return encrypted_packet;
}

void print_message_as_table(unsigned char* data, int rows_max, int columns_max)
{
	int i = 0;
	int j = 0;
	for(i = 0; i < rows_max * columns_max; i++)
	{
		if(j == columns_max)
		{
			printf("\n");
			j = 0;
		}
		j++;
		printf("%c ", data[i]);

	}
	printf("\n");
}
