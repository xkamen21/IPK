/** Author: Daniel Kamenicky **/
/** Subject: IPK, projekt 2, packet sniffer **/
/** Date: 29. 4. 2020  **/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>
#include <time.h>

//knihovny pro praci se zarizenim
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

//knihovny pro IP adrress
#include <arpa/inet.h>

//knihovna pro konvert ip na domain name
#include <netdb.h>

//struktura dat
typedef struct Data{
    bool param_i; //parametr rozhrani
    bool param_p; //parametr filtrovani paketu
    bool param_t; //paramter zobrazeni pouze tcp paketu
    bool param_u; //paramter zobrazeni pouze udp paketu
    bool param_n; //parametr urcujici pocet paketu

    char i_data[50];
    int p_data;
    int n_data;
}Data;

void PrintData (const u_char* data , int Size);
void get_args(Data *data, int argc, char const *argv[]);
void my_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_tcp_packet(const u_char* Buffer, int Size);
void print_udp_packet(const u_char* Buffer, int Size);
void PrintTime();
void PrintSourceIP(const u_char * Buffer);
void PrintDestIP(const u_char * Buffer);


int counter = 0; //pocitadlo pro vypsana data
struct sockaddr_in source,dest; //promenne pro IP adresy

//funkce pro ukonceni programu s vypsanou chybou
void error(char *msg, int retval)
{
    fprintf(stderr, "%s\n", msg);
    exit(retval);
}

//funkce pro argumenty
void get_args(Data *data, int argc, char const *argv[])
{
    //inicializace dat
    data->param_i = false;
    data->param_p = false;
    data->param_t = false;
    data->param_u = false;
    data->param_n = false;
    if(argc == 1){
        return;
    }
    else{
        bool data_after_param = false; //promenna pro kontrolu dat za parametrem
        char tmp[10]; //promenna
        for (int i = 1; i < argc; i++) {
            //parametr --help
            if (!strcmp("--help", argv[i])) {
                if(argc == 2)
                {
                    printf("\t________________________________________ HELP ________________________________________\n");
                    printf("\t| Vypis vsech parametru a jejich funkcnost                                           |\n");
                    printf("\t| Seznam parametru: -i -t --tcp -u --udp -p -n                                       |\n");
                    printf("\t| Parametry '-i', '-p' a '-n' musi obsahovat data ktere chcete programu predat       |\n");
                    printf("\t|   Parametr -i, predava rozhrani na kterem se bude poslouchat (string)              |\n");
                    printf("\t|   Parametr -p, filtrovani paketu podle predaneho portu (integer)                   |\n");
                    printf("\t|   Parametr -n, urcuje pocet paketu, ktere se maji zobrazit (integer)               |\n");
                    printf("\t|   Parametr -t | --tcp, nastaveni zobrazovani pouze tcp packetu                     |\n");
                    printf("\t|   Parametr -u | --udp, nastaveni zobrazovani pouze udp packetu                     |\n");
                    printf("\t‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n");
                    exit(0);
                }
                else
                {
                    error("ERROR: parametr --help nemuze byt kombinovany s jinymi parametry", 1);
                }
            }
            //parametr --tcp nebo -t
            else if(!strcmp("--tcp", argv[i]) || !strcmp("-t", argv[i])){
                //kontrola duplicity parametru
                if(data->param_t)
                {
                    error("ERROR: duplicitni parametr --tcp | -t", 1);
                }
                else if (data_after_param) {
                    error("ERROR: chybejici data parametru", 1);
                }
                else{
                    data->param_t = true;
                    strcpy(tmp, argv[i]);
                }
            }

            //parametr --udp nebo -u
            else if(!strcmp("--udp", argv[i]) || !strcmp("-u", argv[i])){
                //kontrola duplicity parametru
                if(data->param_u)
                {
                    error("ERROR: duplicitni parametr --udp | -u", 1);
                }
                else if (data_after_param) {
                    error("ERROR: chybejici data parametru", 1);
                }
                else{
                    data->param_u = true;
                    strcpy(tmp, argv[i]);
                }
            }

            //parametr -p
            else if(!strcmp("-p", argv[i])){
                //kontrola duplicity parametru
                if(data->param_p)
                {
                    error("ERROR: duplicitni parametr -p", 1);
                }
                else if (data_after_param) {
                    error("ERROR: chybejici data parametru", 1);
                }
                else{
                    data->param_p = true;
                    data_after_param = true;
                    strcpy(tmp, argv[i]);
                }
            }

            //parametr -i
            else if(!strcmp("-i", argv[i])){
                //kontrola duplicity parametru
                if(data->param_i)
                {
                    error("ERROR: duplicitni parametr -i", 1);
                }
                else if (data_after_param) {
                    error("ERROR: chybejici data parametru", 1);
                }
                else{
                    data->param_i = true;
                    data_after_param = true;
                    strcpy(tmp, argv[i]);
                }
            }

            //parametr -n
            else if(!strcmp("-n", argv[i])){
                //kontrola duplicity parametru
                if(data->param_n)
                {
                    error("ERROR: duplicitni parametr -n", 1);
                }
                else if (data_after_param) {
                    error("ERROR: chybejici data parametru", 1);
                }
                else{
                    data->param_n = true;
                    data_after_param = true;
                    strcpy(tmp, argv[i]);
                }
            }

            else{
                //data po parametru
                if(data_after_param)
                {
                    if(!strcmp("-p", tmp))
                    {
                        //kontrola celeho cisla
                        for (unsigned int j = 0; j < strlen(argv[i]); j++) {
                            if(argv[i][j] > 57 || argv[i][j] < 48)
                            {
                                fprintf(stderr, "ERROR: nespravne cislo %s\n", argv[i]);
                                exit(1);
                            }
                        }
                        //prevod ze stringu na int a ulozeni do struktury dat
                        data->p_data = atoi(argv[i]);
                    }
                    else if(!strcmp("-n", tmp))
                    {
                        //kontrola celeho cisla
                        for (unsigned int j = 0; j < strlen(argv[i]); j++) {
                            if(argv[i][j] > 57 || argv[i][j] < 48)
                            {
                                fprintf(stderr, "ERROR: nespravne cislo %s\n", argv[i]);
                                exit(1);
                            }
                        }
                        //prevod ze stringu na int a ulozeni do struktury dat
                        data->n_data = atoi(argv[i]);
                    }
                    else
                    {
                        //ulozeni dat do struktury dat
                        strcpy(data->i_data, argv[i]);
                    }
                    data_after_param = false;
                }
                else
                {
                    error("ERROR: neznamy parametr", 1);
                }
            }

        }
        //kontrola vyskty parametru -n -i -p na konci bez dat
        if (data_after_param) {
            error("ERROR: chybejici data parametru", 1);
        }
    }
}

//vypis zdrojove adresy
void PrintSourceIP(const u_char * Buffer)
{
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    struct in_addr ip;
    struct hostent *hp;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    const char *ipstr = inet_ntoa(source.sin_addr);

    //podminka zda IP adresa existuje
    //zbytecne zde, jelikoz jsme IP adresu prevzali
    if (!inet_aton(ipstr, &ip))
    {
        printf(" %s",ipstr);
        return;
    }

    if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)
    {
        //printf("Jmeno neexisyuje ADRESU!: %s \n", ipstr );
        printf(" %s",ipstr);
        return;
    }

    printf(" %s",hp->h_name);
}

//vypis cilove adresy
void PrintDestIP(const u_char * Buffer)
{
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    struct in_addr ip;
    struct hostent *hp;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    const char *ipstr = inet_ntoa(dest.sin_addr);

    //podminka zda IP adresa existuje
    //zbytecne zde, jelikoz jsme IP adresu prevzali
    if (!inet_aton(ipstr, &ip))
    {
        printf(" %s",ipstr);
        return;
    }

    if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)
    {
        printf(" %s",ipstr);
        return;
    }

    printf(" %s",hp->h_name);
}

//vypis aktualniho casu
void PrintTime()
{
    char buffer[30];
    struct timeval tv;
    time_t curtime;

    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;

    strftime(buffer,30,"%T.",localtime(&curtime));
    printf("%s%ld",buffer,tv.tv_usec);
}

//vypis UDP paketu
void print_udp_packet(const u_char* Buffer , int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    //vypsani casu
    PrintTime();
    //vypsani zdrojove adresy
    PrintSourceIP(Buffer);
    //vypsani zdrojoveho portu
    printf(" : %u",ntohs(udph->source));
    //vzhled
    printf(" >");
    //vypis cilove adresy
    PrintDestIP(Buffer);
    //vypis ciloveho portu
    printf(" : %u\n",ntohs(udph->dest));

    //vypis dat hlavicky
	PrintData(Buffer , header_size);

    printf("\n");

    //vypis dat tela
	PrintData(Buffer + header_size , Size - header_size);

    //vynulovani pocitadla vypsanych dat
    counter = 0;
}

//vypis TCP paketu
void print_tcp_packet(const u_char* Buffer, int Size)
{
    unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    //vypsani casu
    PrintTime(Buffer , header_size);
    //vypsani zdrojove adresy
    PrintSourceIP(Buffer);
    //vypsani zdrojoveho portu
    printf(" : %u",ntohs(tcph->source));
    //vzhled
    printf(" >");
    //vypis cilove adresy
    PrintDestIP(Buffer);
    //vypis ciloveho portu
	printf(" : %u\n",ntohs(tcph->dest));
    //vypis dat hlavicky
    PrintData(Buffer,header_size );

    printf("\n");

    //vypis dat tela
	PrintData(Buffer + header_size , Size - header_size );

    //vynulovani pocitadla vypsanych dat
    counter = 0;
}

// callback funkce pro loop
void my_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
    {
        if(args != NULL)
            fprintf(stderr, "ERROR: chybne predany parametr args\n");
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    	switch (iph->protocol) 
    	{
    		case 6:  //TCP
                //vypis TCP protokolu
                print_tcp_packet(packet , header->caplen);
    			break;

    		case 17: //UDP
                //vypis UDP protokolu
                print_udp_packet(packet , header->caplen);
    			break;

    		default: //Nejkay jiny protokol
                fprintf(stderr, "ERROR: jiny protokol nez UDP nebo TCP..\n\n\n");
    			break;
    	}
    	printf("\n");
    }


//vypis dat z pacektu
// kod prevzat: https://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/
void PrintData (const u_char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //ukonceni radku
		{
			printf("         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					printf("%c",(unsigned char)data[j]); //vypis tisknutelnych dat

				else printf("."); //nahrazeni netisknutelnych dat teckou
			}
			printf("\n");
		}

		if(i%16==0) printf("0x%.4X ", counter); //vypis poradoveho cisla
			printf(" %02X",(unsigned int)data[i]); //vypis dat
            counter++; //pocitadlo vypsanych dat

		if( i==Size-1)  //vypis posledni mezery
		{
			for(j=0;j<15-i%16;j++)
			{
			  printf("   "); //uprava vzhledu
			}
			printf("         ");//uprava vzhledu

			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
				{
				  printf("%c",(unsigned char)data[j]); //vypis tisknutelnych dat
				}
				else
				{
				  printf("."); //nahrazeni netisknutelnych dat teckou
				}
			}
			printf("\n" );
		}
	}
}


int main(int argc, char const *argv[]) {
    //struktura pro ulozeni dat
    Data *sniffer_data = malloc(sizeof(Data));
    //zavolani funkce pro ulozeni dat z parametru programu
    get_args(sniffer_data, argc, argv);

    int count = 1; //counter pro pocet packetu
    //flagy pro nastaveni filtru
    int tcp_and_udp_flag = 0;
    int udp_flag = 0;
    int tcp_flag = 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp; //promenna pro vypis vsech zarizeni
    pcap_t *handle; //promenna pro otevreni zarizeni

    struct bpf_program fp;	//promenna pro prekladany filtr
    char filter[30] = "";	//promenna pro vyraz filtru

    //zjisteni parametru -i
    if(!sniffer_data->param_i)
    {
        //Code source: http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
        int i=0;
        //vyhlednai vsech dostupnych zarizeni
        if(pcap_findalldevs(&interfaces,errbuf)==-1)
        {
            error("ERROR: chyba v findalldevs()", -1);
        }
        printf("Nebyl zadan parametr '-i', zde je vypis vsech aktivnich rozhrani\n");
        //vypsani vsech dostupnych zarizeni
        for(temp=interfaces;temp;temp=temp->next)
        {
            printf("%d  :  %s\n",i++,temp->name);

        }
        exit(0);
    }

    //otevreni rozhrani pro ziskavani packetu
    handle = pcap_open_live(sniffer_data->i_data, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
		 fprintf(stderr, "Nepodarilo se otevrit rozhrani %s: %s\n", sniffer_data->i_data, errbuf);
		 return(2);
	 }

     if (pcap_datalink(handle) != DLT_EN10MB) {
         fprintf(stderr, "Rozhrani %s neposkytuje Ethernet hlavicku - nepodporovano\n", sniffer_data->i_data);
		 return(2);
	}

    //nastaveni dat parametru --udp | -u | --tcp | -t
    if(sniffer_data->param_t)
    {
        strcpy(filter, "tcp");
        tcp_flag = 1;
    }
    else if(sniffer_data->param_u)
    {
        strcpy(filter, "udp");
        udp_flag = 1;
    }
    else
    {
        strcpy(filter, "tcp or udp");
        tcp_and_udp_flag = 1;
    }


    //nastaveni dat parametru -p
    if(sniffer_data->param_p)
    {
        char tmp[10]; //pomocna promenna pro filtr
        sprintf(tmp, "%d", sniffer_data->p_data); //prevedeni cisla portu na string
        //zjisteni kombinaci parametru
        if(tcp_and_udp_flag)
        {
            strcpy(filter, "tcp or udp port ");
            strcat(filter, tmp);
        }
        else if(tcp_flag)
        {
            strcpy(filter, "tcp port ");
            strcat(filter, tmp);
        }
        else if(udp_flag)
        {
            strcpy(filter, "udp port ");
            strcat(filter, tmp);
        }
        else
        {
            strcpy(filter, "tcp or udp port ");
            strcat(filter, tmp);
        }
        //prelozeni filtru
        if (pcap_compile(handle, &fp, filter, 0, 0) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
            return(2);
        }
        //nastaveni filtru
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
            return(2);
        }
    }

    //nastaveni dat parametru -n
    if(sniffer_data->param_n)
    {
        count = sniffer_data->n_data;
    }

	//Vstup do smycky a nacitani packetu
	pcap_loop(handle, count, my_callback, NULL);
	//ukonceni
    pcap_close(handle);
    //vycisteni pameti
    free(sniffer_data);
    return 0;
}
