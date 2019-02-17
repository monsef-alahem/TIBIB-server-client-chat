/*************************************
 *  Chat_client
 *  AUTHOR  :   alahem monsef
 *  EMAIL   :   m.alahem09@gmail.com
 *  VERSION :   -
 *  DATE    :   2017
 *************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//utilisation des thread car fonction recv bloquante
#include <pthread.h>

//les headers special pour réseaux sous windows
#ifdef WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>


//les headers special pour réseaux pour linux
#elif defined (linux)

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//fonction close
#include <unistd.h>
//pour convertir le hostname en Ip
#include <netdb.h> 

#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)

#define KNRM  "\x1B[0m"     //7
#define KRED  "\x1B[31m"    //12
#define KGRN  "\x1B[32m"    //10
#define KYEL  "\x1B[33m"    //14
#define KBLU  "\x1B[34m"    //9
#define KMAG  "\x1B[35m"    //13
#define KCYN  "\x1B[36m"    //11
#define KWHT  "\x1B[37m"    //15

//end color
#define NONE  "\033[0m"

//mettre d'accord windows et linux sur ces noms
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef struct in_addr IN_ADDR;

//si ni linux ni windows on lance une erreur
#else
#error not defined for this platform
#endif
///fin des headers

//taille du packet réseaux
#define PACKET_SIZE 100
//taille du pseudo
#define PSEUDO_SZ 50
//taille de la mémoire temporaire
#define BUFF_SZ 512
//taille des donnée a envoyer
#define DONNEE_SZ 1024

#define TPSATTENTE 5

//codes couleurs
#define GRIS 7
#define VERT 10
#define CYAN 11
#define ROUGE 12
#define JAUNE 14
#define BLANC 15


SOCKET Sock;
pthread_t thread_recevoir;
int niv_securite = 0;

//clé de chiffrage
const unsigned char cle_quasi_indechifrable[100] =
{184,1,40,90,193,199,119,211,103,226,60,127,182,63,133,194,
76,98,171,227,246,185,233,162,141,182,237,226,34,53,244,129,
108,35,7,239,107,145,197,226,74,6,99,75,138,26,241,136,
93,64,223,219,80,228,191,27,45,182,76,169,32,69,172,166,
24,207,242,99,112,87,231,25,207,249,10,219,77,123,213,200,
215,36,66,133,212,209,142,235,8,69,61,252,185,193,94,28,
17,212,16,126};


void sleep_lin_win(unsigned int mseconds);

//fonctions de chiffrage et de déchiffrage
void crypt(int niv_sec, char *pack, int pack_size);
void decrypt(int niv_sec, char *pack, int pack_size);

void *recevoir(void *donnee);//fonction ou se fait la recevoir de donnee envoyer par le serveur

void color(int couleur_du_texte,int couleurDeFond);




int main(void)
{
    char Ip[20];
    unsigned int port = 0;
    char pseudo[PSEUDO_SZ];
    int erreur;
    int i = 0;
    int temps_attente = 0;
    int connecte = 0;

    FILE *config = fopen("ip_port.ini", "r");

    printf("\t\t*****Client Ferkh multiThread*****\n\n\n");

//demmarer socket sous windows
#ifdef WIN32
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);
#endif

    printf("Choisir un pseudo:\n");
    pseudo[0]='\0';
    fgets(pseudo,sizeof pseudo,stdin);
    pseudo[strlen(pseudo)-1]='\0';

    fscanf(config, "%d", &niv_securite);
    printf("======================================================\n"
           "Niveau securite de chiffrage : %d\n"
           "======================================================\n\n", niv_securite);

    fscanf(config, "%d", &port);
    printf("======================================================\n"
           "Port du serveur: %d\n"
           "======================================================\n\n", port);

    fscanf(config, "%s", Ip);
    printf("======================================================\n"
           "Nom de domaine du serveur ou adress ip : %s\n"
           "======================================================\n\n", Ip);

    fclose(config);


    //variables pour capter et stocker l'adress ip 
    struct in_addr addr;
    struct hostent* pHostInfo;
    unsigned long nHostAddress;

    //si l'adresse est un nom de domaine, le convertir en address Ip
    if (Ip[0] < '0' || Ip[0] > '9') {
        pHostInfo = gethostbyname(Ip);
        addr.s_addr = *(u_long *) pHostInfo->h_addr_list[0];
        printf("its domain name !\n");
        if(!pHostInfo){
            printf("Could not resolve host name\n");
            return 0;
        }
        //copier l'address dans pHostInfo
        memset(&nHostAddress, 0, sizeof(nHostAddress));
        memcpy(&nHostAddress,pHostInfo->h_addr,pHostInfo->h_length);
    } else {
        printf("its an ip adress !\n");
    }



    //on creer le socket
    Sock = socket(AF_INET, SOCK_STREAM, 0);
    if ( Sock != INVALID_SOCKET )
    {
        printf("\nSocket client no %d ouvert\n",Sock);

        //remplir la structure sin utilisé par le socket
        SOCKADDR_IN Sin;
        if (Ip[0] < '0' || Ip[0] > '9') {
            Sin.sin_addr.s_addr = inet_addr(inet_ntoa(addr));
        } else {
            Sin.sin_addr.s_addr = inet_addr(Ip);
        }
        Sin.sin_family = AF_INET;
        Sin.sin_port = htons(port);
        //printf("Connection au %s sur le port %d en cours...\n",inet_addr(Ip),port);
        printf("Connection au %s sur le port %d en cours...\n",Ip,port);

        do {
            //on essaye de se connecter au serveur
            erreur = connect(Sock, (SOCKADDR *)&Sin, sizeof Sin);
            if (erreur != SOCKET_ERROR) {
                connecte = 1;
            } else {
                if (temps_attente <= TPSATTENTE) {
                    // attendre 1 seconde
                    sleep_lin_win(1000);
                    temps_attente++;
                } else {
                    printf("Temps de connection trop long");
                    goto deconnection;
                }
            }
        //tant que l'on arrive pas a se connecter
        } while (!connecte);

        printf("Connection au serveur effectue avec succes\n\n");

        char donnee_a_envoyer[DONNEE_SZ];
	
	   //crypt
        crypt(niv_securite, pseudo, PSEUDO_SZ);

        //on envoie le pseudo au serveur
        erreur = send(Sock, pseudo, PSEUDO_SZ, 0);

        //si il y a erreur cela veut dire que l'on a perdu la connection avec le serveur donc on sort
        if (erreur == SOCKET_ERROR)
        {
            goto deconnection;
        }
        //on lance le thread qui va recevoir les donnees du serveur
        pthread_create(&thread_recevoir, NULL, recevoir, NULL);
        do {
            //pour etre sur de ne pas envoyer autre chose que se qui a ete saisie
            donnee_a_envoyer[0] = '\0';

            //on recupere les saisies du clavier
            fgets(donnee_a_envoyer, DONNEE_SZ, stdin);

            i = strlen(donnee_a_envoyer)-1;
            donnee_a_envoyer[i] = 0;

	       //crypt
            crypt(niv_securite, donnee_a_envoyer, DONNEE_SZ);

            //on les envoie au serveur
            erreur = send(Sock, donnee_a_envoyer, DONNEE_SZ, 0);

            if (erreur == SOCKET_ERROR) {
                connecte = 0;
            }
        } while (connecte);


deconnection:


        printf("Connection avec le serveur interrompu\n");
        //on ferme le socket
        closesocket(Sock);
    } else {
        printf("Socket invalide\n");
        return EXIT_FAILURE;
    }
#ifdef WIN32
    //on nettoie le wsa.
    WSACleanup();
#endif
    system("pause");
    return EXIT_SUCCESS;
}

//recevoir le paquet depuis le serveur
void *recevoir(void *donnee)
{
    int i = 0;
    int erreur;
    int connecte = 1;
    char donnee_recu[1024];
    do {
        //recevoir des données
        erreur = recv(Sock, donnee_recu, DONNEE_SZ, 0);
	
	    //decrypt
        decrypt(niv_securite, donnee_recu, DONNEE_SZ);
	
        if (erreur == SOCKET_ERROR) {
            connecte = 0;//voir plus haut
        } else {
            donnee_recu[erreur] = '\0';
            if(donnee_recu[0] == 65)
                color(VERT,0);
            if(donnee_recu[0] == 66)
                color(CYAN,0);
            if(donnee_recu[0] == 67)
                color(ROUGE,0);
            if(donnee_recu[0] == 69)
                color(JAUNE,0);

    	    if(donnee_recu[0] == 65 || donnee_recu[0] == 66 || donnee_recu[0] == 67) {
                printf("%s\n", donnee_recu+1);
        		///sonerie pour avertir l'arrivé d'un nouveau message
                for (i=0;i<9;i++) {
        			putchar(0x07);
        		}
    	    } else {
    		    printf("\t%s\n",donnee_recu+1);
            }  
            donnee_recu[0] = '\0';
        }
    } while (connecte);

    printf("perte de la connection avec le serveur\n");
    closesocket(Sock);//on ferme le socket
    return &donnee;
}


//fonction de coloriage de message
void color(int couleur_du_texte,int couleurDeFond)
{
#ifdef WIN32

    HANDLE H=GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(H,couleurDeFond*16+couleur_du_texte);

#else

    if (couleur_du_texte == 7) {
        printf("%s", KNRM);
    }
    if (couleur_du_texte == 9) {
        printf("%s", KBLU);
    }
    if (couleur_du_texte == 10) {
        printf("%s", KGRN);
    }
    if (couleur_du_texte == 11) {
        printf("%s", KCYN);
    }
    if (couleur_du_texte == 12) {
        printf("%s", KRED);
    }
    if (couleur_du_texte == 14) {
        printf("%s", KYEL);
    }
    if (couleur_du_texte == 15) {
        printf("%s", KWHT);
    }

#endif // WIN32

}

//fonction de pause
#ifdef WIN32
void sleep_lin_win(unsigned int mseconds)
{
    Sleep(mseconds);
}
#endif
#ifdef linux
void sleep_lin_win(unsigned int mseconds)
{
    int sec = mseconds/1000;
    sleep(sec);
}
#endif

void crypt(int niv_sec, char *pack, int pack_size)
{
    int i = 0;
    
    if (niv_sec == 0)
        return;

    if (niv_sec == 1) {

        for (i = 0; i < pack_size; i++) {
            *(pack+i) = (*(pack+i) + i *  19 ) % 256;
        }

    }

    if (niv_sec == 2) {

        for (i = 0; i < pack_size; i++) {
           *(pack+i) = (*(pack+i) + cle_quasi_indechifrable[i % PACKET_SIZE]) % 256;
        }

    }

    if (niv_sec == 3) {

        for (i = 0; i < pack_size; i++) {
            *(pack+i) = (*(pack+i) + (cle_quasi_indechifrable[i % PACKET_SIZE]+ 19 * i) % 256) % 256;
        }

    }
}

void decrypt(int niv_sec, char *pack, int pack_size)
{
    int i = 0;

    if (niv_sec == 0)
        return;

    if (niv_sec == 1) {

        for (i = 0; i < pack_size; i++) {
            *(pack+i) = (*(pack+i) - i *  19 ) % 256;
        }

    }

    if (niv_sec == 2) {

        for (i = 0; i < pack_size; i++) {
            *(pack+i) = (*(pack+i) - cle_quasi_indechifrable[i % PACKET_SIZE]) % 256;
        }

    }

    if (niv_sec == 3) {

        for (i = 0; i < pack_size; i++) {
            *(pack+i) = (*(pack+i) - (cle_quasi_indechifrable[i % PACKET_SIZE]+ 19 * i) % 256) % 256;
        }

    }
}