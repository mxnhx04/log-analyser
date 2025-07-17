#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <set>
#include <regex>
#include <ctime>
#include <iomanip>
#include <stdexcept>

struct LogEntry {
    std::string ip;
    std::string country;
    std::string timestamp;
    std::string method;
    std::string url;
    std::string status;
    std::string size;
    std::string userAgent;
    int responseTime;
};

class LogAnalyzer {
private:
    std::vector<LogEntry> logs;
    std::map<std::string, int> ipRequestCount;
    std::map<std::string, std::vector<std::string>> ipUrls;
    std::map<std::string, int> statusCodes;
    std::map<std::string, int> methodCounts;
    std::set<std::string> suspiciousIPs;
    size_t totalLinesProcessed = 0;
    size_t failedParses = 0;

public:
    void parseLogLine(const std::string& line) {

        // Replace the problematic regex string in parseLogLine with a valid raw string literal
        static const std::regex logRegex(
            R"delim((\S+)\s+-\s+(\S+)\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+)\s+HTTP/[^"]*"\s+(\d+)\s+(\d+)\s+"[^"]*"\s+"([^"]*)"\s+(\d+))delim",
            std::regex_constants::optimize);

        std::smatch matches;
        if (std::regex_match(line, matches, logRegex)) {
            try {
                LogEntry entry;
                entry.ip = matches[1].str();
                entry.country = matches[2].str();
                entry.timestamp = matches[3].str();
                entry.method = matches[4].str();
                entry.url = matches[5].str();
                entry.status = matches[6].str();
                entry.size = matches[7].str();
                entry.userAgent = matches[8].str();
                entry.responseTime = std::stoi(matches[9].str());

                logs.push_back(entry);
                ipRequestCount[entry.ip]++;
                ipUrls[entry.ip].push_back(entry.url);
                statusCodes[entry.status]++;
                methodCounts[entry.method]++;
            }
            catch (const std::exception& e) {
                std::cerr << "Error parsing line: " << e.what() << std::endl;
                failedParses++;
            }
        }
        else {
            failedParses++;
        }
        totalLinesProcessed++;
    }

    void loadLogs(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open log file: " + filename);
        }

        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                parseLogLine(line);
            }
        }
    }

    void detectBotActivity() {
        std::cout << "=== BOT DETECTION ANALYSIS ===" << std::endl;
        std::cout << "Total requests analyzed: " << logs.size() << std::endl;
        std::cout << "Failed to parse: " << failedParses << " lines ("
            << std::fixed << std::setprecision(1)
            << (static_cast<double>(failedParses) / totalLinesProcessed * 100)
            << "%)" << std::endl;
        std::cout << "Unique IP addresses: " << ipRequestCount.size() << std::endl;

        // High-frequency IPs (potential bots)
        std::cout << "\nHIGH-FREQUENCY IPs (>3 requests in 32 seconds):" << std::endl;
        for (const auto& pair : ipRequestCount) {
            if (pair.second > 3) {
                std::cout << "IP: " << pair.first << " - " << pair.second << " requests" << std::endl;
                suspiciousIPs.insert(pair.first);
            }
        }

        // Analyze suspicious patterns
        std::cout << "\nSUSPICIOUS PATTERNS DETECTED:" << std::endl;

        // Check for unusual HTTP methods
        std::cout << "HTTP Methods:" << std::endl;
        for (const auto& pair : methodCounts) {
            std::cout << "  " << pair.first << ": " << pair.second << " requests";
            if (pair.first == "DELETE" || pair.first == "PUT") {
                std::cout << " (SUSPICIOUS - unusual for regular browsing)";
            }
            std::cout << std::endl;
        }

        // Check for 404 errors (potential probing)
        std::cout << "\nStatus Code Analysis:" << std::endl;
        for (const auto& pair : statusCodes) {
            std::cout << "  " << pair.first << ": " << pair.second << " requests";
            if (pair.first == "404") {
                std::cout << " (Potential bot probing)";
            }
            std::cout << std::endl;
        }

        // Analyze URL patterns for each suspicious IP
        std::cout << "\nURL PATTERN ANALYSIS:" << std::endl;
        for (const std::string& ip : suspiciousIPs) {
            std::cout << "IP " << ip << " accessed:" << std::endl;
            const auto& urls = ipUrls[ip];
            std::set<std::string> uniqueUrls(urls.begin(), urls.end());
            for (const std::string& url : uniqueUrls) {
                std::cout << "  " << url << std::endl;
            }
            std::cout << std::endl;
        }
    }

    void generateReport() {
        std::cout << "\n=== TRAFFIC ANALYSIS SUMMARY ===" << std::endl;

        constexpr double analysisPeriod = 32.0; // seconds
        double requestsPerSecond = static_cast<double>(logs.size()) / analysisPeriod;
        std::cout << "Traffic rate: " << std::fixed << std::setprecision(2)
            << requestsPerSecond << " requests/second" << std::endl;

        int botRequests = 0;
        for (const auto& pair : ipRequestCount) {
            if (pair.second > 3) {
                botRequests += pair.second;
            }
        }

        if (!logs.empty()) {
            double botPercentage = (static_cast<double>(botRequests) / logs.size()) * 100;
            std::cout << "Estimated bot traffic: " << std::fixed << std::setprecision(1)
                << botPercentage << "%" << std::endl;
            std::cout << "Legitimate traffic: " << (100 - botPercentage) << "%" << std::endl;
        }
        else {
            std::cout << "No valid log entries to analyze." << std::endl;
        }
    }

    void recommendations() {
        std::cout << "\n=== COST-EFFECTIVE RECOMMENDATIONS ===" << std::endl;
        std::cout << "1. Implement rate limiting (1-2 requests/second per IP)" << std::endl;
        std::cout << "2. Block unusual HTTP methods (DELETE, PUT) on public endpoints" << std::endl;
        std::cout << "3. Monitor 404 patterns and implement IP blocking" << std::endl;
        std::cout << "4. Add simple CAPTCHA for high-frequency requests" << std::endl;
        std::cout << "5. Consider CDN with basic DDoS protection" << std::endl;
        std::cout << "6. Implement logging rotation and compression to save space" << std::endl;
        std::cout << "7. Use a more efficient log format (e.g., JSON) for easier parsing" << std::endl;
    }
};

int main() {
    try {
        LogAnalyzer analyzer;

        // Load logs from file
        std::cout << "Loading server logs..." << std::endl;
        analyzer.loadLogs("C:\Users\manha\source\repos\manha\sample-log55.txt");

        // Perform analysis
        analyzer.detectBotActivity();
        analyzer.generateReport();
        analyzer.recommendations();

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}