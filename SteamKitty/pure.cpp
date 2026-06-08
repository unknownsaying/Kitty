// pure_steam.cpp - Pure C++17, minimal dependencies
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <regex>
#include <fstream>
#include <chrono>
#include <thread>
#include <cstring>
#include <memory>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <arpa/inet.h>
#endif

class PureSteamClient {
private:
    // Pure socket HTTP GET implementation
    std::string httpGet(const std::string& host, const std::string& path) {
        std::string response;
        
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
        
        struct addrinfo hints = {}, *addr = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(host.c_str(), "80", &hints, &addr) != 0) {
            return "";
        }
        
        int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            freeaddrinfo(addr);
            return "";
        }
        
        if (connect(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            freeaddrinfo(addr);
            return "";
        }
        
        freeaddrinfo(addr);
        
        // Build HTTP request
        std::string request = "GET " + path + " HTTP/1.1\r\n"
                              "Host: " + host + "\r\n"
                              "User-Agent: PureSteamClient/1.0\r\n"
                              "Connection: close\r\n\r\n";
        
        send(sock, request.c_str(), request.length(), 0);
        
        // Read response
        char buffer[4096];
        int bytes;
        while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes] = '\0';
            response += buffer;
        }
        
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        
        // Extract body (skip HTTP headers)
        size_t bodyPos = response.find("\r\n\r\n");
        if (bodyPos != std::string::npos) {
            return response.substr(bodyPos + 4);
        }
        return response;
    }
    
    // Pure string-based JSON parser (minimal)
    std::string extractJsonValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\"";
        size_t keyPos = json.find(searchKey);
        if (keyPos == std::string::npos) return "";
        
        size_t colonPos = json.find(':', keyPos);
        if (colonPos == std::string::npos) return "";
        
        size_t valueStart = json.find_first_not_of(" \t\n\r", colonPos + 1);
        if (valueStart == std::string::npos) return "";
        
        if (json[valueStart] == '"') {
            size_t valueEnd = json.find('"', valueStart + 1);
            if (valueEnd != std::string::npos) {
                return json.substr(valueStart + 1, valueEnd - valueStart - 1);
            }
        } else {
            size_t valueEnd = json.find_first_of(",}\n", valueStart);
            if (valueEnd != std::string::npos) {
                return json.substr(valueStart, valueEnd - valueStart);
            }
        }
        return "";
    }
    
public:
    struct Game {
        int appId;
        std::string name;
        std::string price;
        bool isFree;
        std::string developers;
        std::string publishers;
    };
    
    Game getGameInfo(int appId) {
        Game game;
        game.appId = appId;
        game.isFree = false;
        
        std::string url = "/api/appdetails?appids=" + std::to_string(appId);
        std::string response = httpGet("store.steampowered.com", url);
        
        // Parse game name
        game.name = extractJsonValue(response, "name");
        if (game.name.empty()) {
            game.name = "Unknown";
        }
        
        // Check if free
        std::string priceStr = extractJsonValue(response, "final");
        if (priceStr == "0") {
            game.isFree = true;
            game.price = "Free";
        } else {
            game.price = extractJsonValue(response, "final_formatted");
            if (game.price.empty()) game.price = "Unknown";
        }
        
        // Parse developers
        std::string devs = extractJsonValue(response, "developers");
        if (!devs.empty() && devs.front() == '[') {
            // Extract first developer from array
            size_t firstQuote = devs.find('"');
            if (firstQuote != std::string::npos) {
                size_t secondQuote = devs.find('"', firstQuote + 1);
                if (secondQuote != std::string::npos) {
                    game.developers = devs.substr(firstQuote + 1, secondQuote - firstQuote - 1);
                }
            }
        } else {
            game.developers = devs;
        }
        
        return game;
    }
    
    std::vector<int> getTopGames(int limit = 50) {
        std::vector<int> appIds;
        
        // Use Steam Spy public API (no key required)
        std::string response = httpGet("steamspy.com", "/api.php?request=top100in2weeks");
        
        // Parse JSON array of objects like {"730": {...}, "570": {...}}
        std::regex appIdRegex("\"([0-9]+)\":\\{");
        std::smatch matches;
        std::string::const_iterator searchStart(response.cbegin());
        
        while (std::regex_search(searchStart, response.cend(), matches, appIdRegex) && appIds.size() < limit) {
            if (matches.size() > 1) {
                appIds.push_back(std::stoi(matches[1].str()));
            }
            searchStart = matches[0].second;
        }
        
        return appIds;
    }
    
    std::string getSteamStoreLink(int appId) {
        return "https://store.steampowered.com/app/" + std::to_string(appId);
    }
};

// Pure C++ Game Database (No SQL, just CSV)
class PureGameDatabase {
private:
    std::string filename;
    
public:
    PureGameDatabase(const std::string& fname = "steam_games.csv") : filename(fname) {}
    
    void saveGame(const PureSteamClient::Game& game) {
        std::ofstream file(filename, std::ios::app);
        if (file.tellp() == 0) {
            file << "AppID,Name,Price,IsFree,Developers\n";
        }
        file << game.appId << ","
             << "\"" << game.name << "\","
             << "\"" << game.price << "\","
             << (game.isFree ? "Yes" : "No") << ","
             << "\"" << game.developers << "\"\n";
        file.close();
    }
    
    std::vector<PureSteamClient::Game> loadGames() {
        std::vector<PureSteamClient::Game> games;
        std::ifstream file(filename);
        std::string line;
        
        bool firstLine = true;
        while (std::getline(file, line)) {
            if (firstLine) { firstLine = false; continue; }
            
            std::stringstream ss(line);
            PureSteamClient::Game game;
            std::string token;
            
            std::getline(ss, token, ','); game.appId = std::stoi(token);
            std::getline(ss, token, ','); 
            if (token.front() == '"') {
                game.name = token.substr(1, token.length() - 2);
            } else {
                game.name = token;
            }
            std::getline(ss, token, ',');
            if (token.front() == '"') {
                game.price = token.substr(1, token.length() - 2);
            } else {
                game.price = token;
            }
            std::getline(ss, token, ','); game.isFree = (token == "Yes");
            std::getline(ss, token); 
            if (token.front() == '"') {
                game.developers = token.substr(1, token.length() - 2);
            } else {
                game.developers = token;
            }
            
            games.push_back(game);
        }
        return games;
    }
};

// Pure C++ Steam Game Launcher
class PureSteamLauncher {
public:
    static bool launchGame(int appId) {
        std::string url = "steam://rungameid/" + std::to_string(appId);
        
#ifdef _WIN32
        // Windows: Use ShellExecute (only Windows API, no extra deps)
        ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        return true;
#elif __APPLE__
        std::string cmd = "open '" + url + "'";
        return system(cmd.c_str()) == 0;
#else
        std::string cmd = "xdg-open '" + url + "'";
        return system(cmd.c_str()) == 0;
#endif
    }
    
    static bool openStorePage(int appId) {
        std::string url = "https://store.steampowered.com/app/" + std::to_string(appId);
        
#ifdef _WIN32
        ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        return true;
#elif __APPLE__
        std::string cmd = "open '" + url + "'";
        return system(cmd.c_str()) == 0;
#else
        std::string cmd = "xdg-open '" + url + "'";
        return system(cmd.c_str()) == 0;
#endif
    }
};

// Main program - Pure C++ Steam Explorer
int main() {
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║     PURE STEAM GAME EXPLORER         ║\n";
    std::cout << "║     C++ | No Dependencies | Clean    ║\n";
    std::cout << "╚══════════════════════════════════════╝\n\n";
    
    PureSteamClient steam;
    PureGameDatabase db;
    bool running = true;
    
    while (running) {
        std::cout << "\n┌────────────────────────────────────┐\n";
        std::cout << "│ 1. Search Game by App ID           │\n";
        std::cout << "│ 2. Browse Top 20 Games             │\n";
        std::cout << "│ 3. Launch Steam Game               │\n";
        std::cout << "│ 4. View Saved Games                │\n";
        std::cout << "│ 5. Export Game to Database         │\n";
        std::cout << "│ 0. Exit                            │\n";
        std::cout << "└────────────────────────────────────┘\n";
        std::cout << "Choice: ";
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1: {
                int appId;
                std::cout << "Enter Steam App ID (e.g., 730 for CS:GO): ";
                std::cin >> appId;
                
                std::cout << "\nFetching game info...\n";
                PureSteamClient::Game game = steam.getGameInfo(appId);
                
                std::cout << "\n┌────────────────────────────────────┐\n";
                std::cout << "│ GAME INFORMATION                    │\n";
                std::cout << "├────────────────────────────────────┤\n";
                std::cout << "│ App ID: " << game.appId << "\n";
                std::cout << "│ Name:   " << game.name << "\n";
                std::cout << "│ Price:  " << game.price << "\n";
                std::cout << "│ Free:   " << (game.isFree ? "Yes" : "No") << "\n";
                std::cout << "│ Store:  " << steam.getSteamStoreLink(appId) << "\n";
                std::cout << "└────────────────────────────────────┘\n";
                break;
            }
            
            case 2: {
                std::cout << "\nFetching top games from Steam...\n";
                std::vector<int> topGames = steam.getTopGames(20);
                
                std::cout << "\n┌────────────────────────────────────┐\n";
                std::cout << "│ TOP 20 STEAM GAMES                 │\n";
                std::cout << "├────────────────────────────────────┤\n";
                
                for (size_t i = 0; i < topGames.size(); i++) {
                    PureSteamClient::Game game = steam.getGameInfo(topGames[i]);
                    std::cout << "│ " << (i+1) << ". " << game.name;
                    for (int j = game.name.length(); j < 28; j++) std::cout << " ";
                    std::cout << "│\n";
                    std::cout << "│    ID: " << game.appId << "\n";
                }
                std::cout << "└────────────────────────────────────┘\n";
                break;
            }
            
            case 3: {
                int appId;
                std::cout << "Enter App ID to launch: ";
                std::cin >> appId;
                
                if (PureSteamLauncher::launchGame(appId)) {
                    std::cout << "Launching Steam game " << appId << "...\n";
                } else {
                    std::cout << "Failed to launch game.\n";
                }
                break;
            }
            
            case 4: {
                std::vector<PureSteamClient::Game> savedGames = db.loadGames();
                if (savedGames.empty()) {
                    std::cout << "No saved games. Use option 5 to save games.\n";
                } else {
                    std::cout << "\n┌────────────────────────────────────┐\n";
                    std::cout << "│ SAVED GAMES                        │\n";
                    std::cout << "├────────────────────────────────────┤\n";
                    for (const auto& game : savedGames) {
                        std::cout << "│ " << game.name << " (" << game.appId << ")\n";
                        std::cout << "│   Price: " << game.price << "\n";
                    }
                    std::cout << "└────────────────────────────────────┘\n";
                }
                break;
            }
            
            case 5: {
                int appId;
                std::cout << "Enter App ID to save: ";
                std::cin >> appId;
                
                PureSteamClient::Game game = steam.getGameInfo(appId);
                db.saveGame(game);
                std::cout << "Game saved to database.\n";
                break;
            }
            
            case 0:
                running = false;
                std::cout << "Goodbye!\n";
                break;
                
            default:
                std::cout << "Invalid choice.\n";
        }
        
        if (running && choice != 0) {
            std::cout << "\nPress Enter to continue...";
            std::cin.ignore();
            std::cin.get();
        }
    }
    
    return 0;
}
