#include <iostream>
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Renkler
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

using namespace std;

// Basit Saldırı İmzaları (Signatures)
// Gerçek bir IDS'te binlerce imza olur.
struct Signature {
    string pattern;
    string name;
};

vector<Signature> signatures = {
    {"<script>", "XSS Attack Attempt"},
    {"UNION SELECT", "SQL Injection Attempt"},
    {"/etc/passwd", "LFI / Path Traversal Attack"},
    {"cmd.exe", "Remote Command Execution (RCE)"},
    {"whoami", "Suspicious Command Execution"}
};

// Paketin içindeki veriyi (Payload) analiz eden fonksiyon
void analyzePayload(unsigned char* buffer, int size, string sourceIP, string destIP) {
    // Binary veriyi string'e çevirmeye çalış (Basit analiz için)
    string data = "";
    for (int i = 0; i < size; i++) {
        if (isprint(buffer[i])) {
            data += buffer[i];
        }
    }

    // İmza kontrolü
    for (const auto& sig : signatures) {
        if (data.find(sig.pattern) != string::npos) {
            cout << RED << "\n[!!!] SALDIRI TESPİT EDİLDİ [!!!]" << RESET << endl;
            cout << RED << " [*] Tehdit Türü: " << sig.name << RESET << endl;
            cout << YELLOW << " [*] Kaynak: " << sourceIP << " -> Hedef: " << destIP << RESET << endl;
            cout << " [*] İçerik Parçası: " << sig.pattern << endl;
            cout << "------------------------------------------------" << endl;
        }
    }
}

void startIDS() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    
    // Raw Socket oluştur
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    if (sock_raw < 0) {
        perror("Socket Error");
        cout << RED << "[!] Hata: Raw Socket açılamadı. Root yetkisi var mı?" << RESET << endl;
        return;
    }

    cout << GREEN << "[*] NetGuard IDS Başlatıldı. Ağ trafiği analiz ediliyor..." << RESET << endl;
    cout << CYAN << "[*] Yüklenen İmzalar: " << signatures.size() << " adet." << RESET << endl;

    while (true) {
        socklen_t saddr_size = sizeof(saddr);
        
        // Paketi yakala
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, (struct sockaddr *)&saddr, &saddr_size);
        
        if (data_size < 0) continue;

        // IP Header'ı ayıkla
        struct iphdr *iph = (struct iphdr *)buffer;
        unsigned short iphdrlen = iph->ihl * 4;

        // TCP Header'ı ayıkla
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
        int header_size = iphdrlen + tcph->doff * 4;

        // Payload (Veri) kısmına ulaş
        // Toplam boyut - Header boyutları = Veri boyutu
        int payload_size = data_size - header_size;

        if (payload_size > 0) {
            struct in_addr source_ip, dest_ip;
            source_ip.s_addr = iph->saddr;
            dest_ip.s_addr = iph->daddr;
            
            // Veriyi analize gönder
            analyzePayload(buffer + header_size, payload_size, inet_ntoa(source_ip), inet_ntoa(dest_ip));
        }
    }
    
    close(sock_raw);
    free(buffer);
}

int main() {
    if (getuid() != 0) {
        cout << RED << "[!] HATA: NetGuard ROOT yetkisi gerektirir." << RESET << endl;
        cout << "Lütfen 'sudo ./netguard' ile çalıştırın." << endl;
        return 1;
    }

    cout << R"(
    _   __      __  ______                      __
   / | / /___  / /_/ ____/u__  ______ __________/ /
  /  |/ / _ \/ __/ / __/ / / / / __ `/ ___/ __  / 
 / /|  /  __/ /_/ /_/ / /_/ / / /_/ / /  / /_/ /  
/_/ |_/\___/\__/\____/\__,_/\__,_/_/   \__,_/   
    Network Intrusion Detection System v1.0
    )" << endl;

    startIDS();
    return 0;
}
