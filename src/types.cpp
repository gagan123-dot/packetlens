#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <string>
#include <initializer_list>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// True if s == d, or s ends with "." + d
// e.g. "www.netflix.com" matches "netflix.com", but "notnetflix.com" does not.
static bool domainMatches(const std::string& s, const std::string& d) {
    if (s == d) return true;
    return s.size() > d.size() &&
           s.compare(s.size() - d.size(), d.size(), d) == 0 &&
           s[s.size() - d.size() - 1] == '.';
}

// True if s matches any domain in the list
static bool matchesAny(const std::string& s, std::initializer_list<const char*> domains) {
    for (const char* d : domains) {
        if (domainMatches(s, d)) return true;
    }
    return false;
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string s = sni;
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // YouTube (checked before Google, since googlevideo.com is YouTube's CDN)
    if (matchesAny(s, {"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
                       "youtube-nocookie.com", "yt3.ggpht.com"})) {
        return AppType::YOUTUBE;
    }
    
    // Google
    if (matchesAny(s, {"google.com", "gstatic.com", "googleapis.com", "ggpht.com",
                       "gvt1.com", "googleusercontent.com"})) {
        return AppType::GOOGLE;
    }
    
    // Instagram (checked before Facebook, both are Meta)
    if (matchesAny(s, {"instagram.com", "cdninstagram.com"})) {
        return AppType::INSTAGRAM;
    }
    
    // WhatsApp
    if (matchesAny(s, {"whatsapp.com", "whatsapp.net", "wa.me"})) {
        return AppType::WHATSAPP;
    }
    
    // Facebook/Meta
    if (matchesAny(s, {"facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com"})) {
        return AppType::FACEBOOK;
    }
    
    // Twitter/X
    if (matchesAny(s, {"twitter.com", "twimg.com", "x.com", "t.co"})) {
        return AppType::TWITTER;
    }
    
    // Netflix
    if (matchesAny(s, {"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"})) {
        return AppType::NETFLIX;
    }
    
    // Amazon
    if (matchesAny(s, {"amazon.com", "amazon.in", "amazonaws.com", "cloudfront.net"})) {
        return AppType::AMAZON;
    }
    
    // Microsoft
    if (matchesAny(s, {"microsoft.com", "msn.com", "office.com", "office365.com",
                       "azure.com", "azureedge.net", "live.com", "outlook.com",
                       "bing.com", "windows.com", "microsoftonline.com"})) {
        return AppType::MICROSOFT;
    }
    
    // Apple
    if (matchesAny(s, {"apple.com", "icloud.com", "mzstatic.com", "itunes.com"})) {
        return AppType::APPLE;
    }
    
    // Telegram
    if (matchesAny(s, {"telegram.org", "telegram.me", "t.me"})) {
        return AppType::TELEGRAM;
    }
    
    // TikTok
    if (matchesAny(s, {"tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com"})) {
        return AppType::TIKTOK;
    }
    
    // Spotify
    if (matchesAny(s, {"spotify.com", "scdn.co"})) {
        return AppType::SPOTIFY;
    }
    
    // Zoom
    if (matchesAny(s, {"zoom.us", "zoom.com"})) {
        return AppType::ZOOM;
    }
    
    // Discord
    if (matchesAny(s, {"discord.com", "discordapp.com", "discord.gg"})) {
        return AppType::DISCORD;
    }
    
    // GitHub
    if (matchesAny(s, {"github.com", "githubusercontent.com", "github.io"})) {
        return AppType::GITHUB;
    }
    
    // Cloudflare
    if (matchesAny(s, {"cloudflare.com", "cloudflare.net"})) {
        return AppType::CLOUDFLARE;
    }
    
    // SNI is present but not recognized, so mark as generic HTTPS
    return AppType::HTTPS;
}

} // namespace DPI