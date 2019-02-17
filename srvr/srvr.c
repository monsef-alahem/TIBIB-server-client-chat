/*************************************
 *  Chat multi-threads server
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

//les headers special pour réseaux pour windows
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

//abreviation des structures
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
#define pseudo_SZ 50
//taille de la mémoire temporaire
#define BUFF_SZ 512
//taille des donnée a envoyer
#define donnee_SZ 1024

#define MAX_CLIENT 10

//structure ou sera enregistre les information pour chaque client
typedef struct Client
{
    char pseudo[50];
    SOCKET client_socket;
    int connecte;
    pthread_t thread_de_recevoir;
}Client;

static Client client[MAX_CLIENT];

int new_thread_id = 0;
int server_full = 0;

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

//fonction qui ecoute un client et renvoie les donnees recu aux autres clients
void *recevoir(void *data);

//envoie donnee au client renvoie 1 si succes sinon 0
int envoi_donnee(SOCKET client_socket,char *donnee);

//met en ecoute revoie 1 si succes sinon 0
int ecoute();
SOCKET server_sock;
int ret = 0;
SOCKADDR_IN Sin = {0};
unsigned short port = 0;
int niv_securite = 0;




int main(void)
{

    int i = 0;
    int j = 0;
    char buff[512];
    

    printf("\t\t*****Serveur Ferkh multiThread*****\n\n\n");

    FILE *config = fopen("ip_port2.ini", "r");

    fscanf(config, "%d", &niv_securite);
    printf("======================================================\n"
           "Niveau securite de chiffrage : %d\n"
           "======================================================\n\n",niv_securite);

    fscanf(config, "%d", &port);
    printf("======================================================\n"
           "Port du serveur: %d\n"
           "======================================================\n\n", port);

    fclose(config);



    if (ecoute())
    {
        printf("Le Serveur ecoute sur le port %d\nEn attente de la connections des clients\n",port);//si 1, c ok
    }
    else
    {
        printf("Erreur lors de la mise en ecoute sur le port no %d\n",port);//0 erreur, on est obliger de sortir
        system("pause");
        return 0;
    }

    i = 0;

    do {

        if (i>=MAX_CLIENT) {
            printf("Serveur Plein\n");
            //indiquer que le Serveur est saturer
            server_full = 1;
            //eteindre le socket reception
            shutdown(server_sock, 1);
            closesocket(server_sock);
            do {
                //dormir le prog 1 seconde
                sleep_lin_win(1000);
            //tant que le serveur n'est pa plein
            } while (server_full);
            if (ecoute()) {
                printf("Serveur en attente de client\n");
            } else {
                printf("Erreur lors de la mise en ecoute sur le port no %d\n", port);
                system("pause");
                return 0;
            }
            //réinitialiser i pour prochain scan
            i = 0;
        } else {
            //si serveur toujours libre
            if (client[i].connecte == 0) {
                printf("Emplacement libre trouver : %d\n", i);
                sleep_lin_win(10);
                SOCKADDR_IN CSin = {0};
                int sizeofcsin = sizeof(CSin);
#ifdef linux
                client[i].client_socket = accept(server_sock, (SOCKADDR *)&CSin, (socklen_t *)&sizeofcsin);//on accepte la connection
#endif

#ifdef WiN32   
                client[i].client_socket = accept(server_sock, (SOCKADDR *)&CSin, &sizeofcsin);//on accepte la connection
#endif


                if ( client[i].client_socket != INVALID_SOCKET ) {

                    //mettre le statut du client a 1
                    client[i].connecte = 1;

                    //recevoir le pseudo
                    ret = recv(client[i].client_socket, client[i].pseudo, pseudo_SZ, 0);
                    decrypt(niv_securite, client[i].pseudo, pseudo_SZ);

                    printf("Client no %d connecte sous le pseudo: %s ip:\n", i, client[i].pseudo);

                    memset(buff, 0, sizeof(buff));

                    //composer le message d'information
                    buff[0] = 'B';
                    strcpy(buff + 1, client[i].pseudo);
                    strcat(buff, " s'est connecter\n");

                    //dire a tout le monde que le nouveau client est connecté
                    for (j = 0; j < MAX_CLIENT; j++) {
                        //sauter le nouveau client qui vient de se connecté
                        if (j != i) {
                            crypt(niv_securite, buff, BUFF_SZ);
                            ret = send(client[j].client_socket, buff, BUFF_SZ, 0);
                        }
                    }

                    //vider le buff
                    memset(buff, 0, sizeof(buff));
                    buff[0] = 'A';

                    //envoyer la liste des connectés
                    for (j = 0; j < MAX_CLIENT; j++) {
                        if (client[j].connecte) {
                            strcat(buff, client[j].pseudo);
                            strcat(buff, " est connecter !\n");
                        } 
                    }

                    //envoi du handshake
                    crypt(niv_securite, buff, BUFF_SZ);
                    ret = send(client[i].client_socket, buff, BUFF_SZ, 0);

                    //enregistrer le id du client
                    new_thread_id = i;

                    //on lance le thread ou va etre recu les donnes de ce client
                    pthread_create(&client[i].thread_de_recevoir, NULL, recevoir, NULL);

                    //on repasse i a 0 pour une prochaine recherche d'emplacement libre
                    i = 0;
                } else {
                    printf("Erreur initialisation socket client !\n");
                }



            }
            //prochain client
            i++;
        }
    } while(1);
#ifdef WIN32
    WSACleanup();
#endif
    system("pause");
    return 0;
}

void *recevoir(void *donnee)
{
    int ret_recevoir;
    int i = 0;
    int j = 0;
    int actual_thread_id = new_thread_id;
    char donnee_recu[1024];
    char donnee_a_envoyer[1024];
    int connecte = 1;

    do {
        i = 0;

        //on recoit les donnees (fonction dite "bloquante")
        ret_recevoir = recv(client[actual_thread_id].client_socket, donnee_recu, donnee_SZ, 0);
        decrypt(niv_securite, donnee_recu, donnee_SZ);
        
        //toujours en connection avec le client
        if (ret_recevoir != SOCKET_ERROR) {
            donnee_recu[ret_recevoir] = '\0';
            do {
                //verifier que le client est bien connecté
                if (client[i].connecte == 1) {
                    //ne pas envoyer données au envoyeur
                    if (i != actual_thread_id) {
                        for (j = 0; j < 100; j++)
                            donnee_a_envoyer[j] = '\0';
                        donnee_a_envoyer[0] = 'E';
                        strcpy(donnee_a_envoyer+1,client[actual_thread_id].pseudo);
                        strcat(donnee_a_envoyer," : ");
                        strcat(donnee_a_envoyer,donnee_recu);

                        crypt(niv_securite, donnee_a_envoyer, donnee_SZ);

                        //si envoie echoue
                        if (!envoi_donnee(client[i].client_socket,donnee_a_envoyer)) {
                            printf("%s se deconnecte\n", client[i].pseudo);
                            //fermer socket client
                            closesocket(client[i].client_socket);
                            //indiquer que emplacement est libre
                            client[i].connecte = 0;
                            //reinitialiser in dicateur serveur plein
                            server_full = 0;
                        }

                        memset(donnee_a_envoyer, 0, donnee_SZ);
                    }
                }
                //passer au prochain client
                i++;
            } while (i < MAX_CLIENT);
            i = 0;
        //plus de connection avec le client
        } else {

            printf("%s se deconnecte\n", client[actual_thread_id].pseudo);
            donnee_a_envoyer[0] = 'C';
            strcpy(donnee_a_envoyer+1, client[actual_thread_id].pseudo);
            strcat(donnee_a_envoyer, " se deconecte\n");

            crypt(niv_securite, donnee_a_envoyer, donnee_SZ);

            for (j = 0; j < MAX_CLIENT; j++)
                envoi_donnee(client[j].client_socket,donnee_a_envoyer);

            memset(donnee_a_envoyer, 0, donnee_SZ);

            //fermer socket de ce thread
            shutdown(client[actual_thread_id].client_socket, 2);
            closesocket(client[actual_thread_id].client_socket);

            //indiquer que cet emplacement est desormais libre
            client[actual_thread_id].connecte = 0;

            server_full = 0;

            //declarer que le client n'est plus
            connecte = 0;
        }
    } while (connecte);

    return &donnee;
}



int envoi_donnee(SOCKET client_socket,char *donnee)
{
    int envoi_success;

    //envoyer les donnees
    envoi_success = send(client_socket, donnee, donnee_SZ, 0);
    if (envoi_success != SOCKET_ERROR) {
        return 1;
    }
    return 0;
}



int ecoute()
{
//pour windows seulement
#ifdef WIN32
     WSADATA WSAData;

    //initaliser winsock
    WSAStartup(MAKEWORD(2,0), &WSAData);
#endif
   

    //structure qui va contenir les informations  de notre socket serveur
    SOCKADDR_IN Sin = {0};

    //creation du socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    //si creation ok
    if (server_sock != INVALID_SOCKET) {

        //on rempli la structure
        Sin.sin_addr.s_addr    = htonl(INADDR_ANY);
        Sin.sin_family    = AF_INET;
        Sin.sin_port    = htons(port);

        ret = bind(server_sock, (SOCKADDR *)&Sin, sizeof(Sin));

        //si ok
        if (ret != SOCKET_ERROR) {
            //on commence ll'ecoute (l'attente de client)
            ret = listen(server_sock, 2);

            //si tout c'est bien passer
            if (ret != SOCKET_ERROR) {
                return 1;
            }
        }
    }
    return 0;
}



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