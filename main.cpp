#include <algorithm>
#include <bit>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "decrypt.hpp"


constexpr uint32_t ReadLE32(const unsigned char* ptr)
{
    return static_cast<uint32_t>(ptr[0])
        | (static_cast<uint32_t>(ptr[1]) << 8)
        | (static_cast<uint32_t>(ptr[2]) << 16)
        | (static_cast<uint32_t>(ptr[3]) << 24);
}

bool DecryptMetadata(std::span<const unsigned char> encryptedData,
    std::vector<unsigned char>& decryptedData)
{
    if (encryptedData.size() < 8)
    {
        std::cout << "[!] File too small to be valid metadata\n";
        return false;
    }

    const uint32_t magic = ReadLE32(encryptedData.data());
    if (magic != 0x1357FEDA)
    {
        std::cout << std::hex << "[!] Invalid magic number: 0x"
            << magic << std::dec << "\n";
        return false;
    }

    const uint32_t encryptedSize = ReadLE32(encryptedData.data() + 4);
    std::cout << "Encrypted data size: " << encryptedSize << " bytes\n"
        << "Total file size: " << encryptedData.size() << " bytes\n";

    if (encryptedSize == 0 || encryptedSize > encryptedData.size())
    {
        std::cout << "[!] Invalid encrypted size\n";
        return false;
    }

    const size_t headerSize = encryptedData.size() - encryptedSize;
    std::cout << "Header size: " << headerSize
        << " bytes (0x" << std::hex << headerSize << std::dec << ")\n";

    if (headerSize < 0x108 + 64)
    {
        std::cout << "[!] Header too small for bytecode extraction\n";
        return false;
    }

    const unsigned char* bytecode = encryptedData.data() + 0x108;
    const unsigned char* key = encryptedData.data() + 8;
    const size_t dataStart = headerSize;

    std::cout << "Data starts at offset: 0x"
        << std::hex << dataStart << std::dec << "\n";

    std::vector<unsigned char> workingData(
        encryptedData.begin() + static_cast<std::ptrdiff_t>(dataStart),
        encryptedData.begin() + static_cast<std::ptrdiff_t>(dataStart + encryptedSize));

    for (size_t offset = 0; offset < encryptedSize; offset += 64)
    {
        const size_t chunkSize = std::min<size_t>(64, encryptedSize - offset);
        DecryptionChunk(reinterpret_cast<std::intptr_t>(bytecode),
            64,
            const_cast<_BYTE*>(key),
            reinterpret_cast<std::intptr_t>(workingData.data() + offset),
            static_cast<unsigned int>(chunkSize));
    }

    constexpr std::string_view signature = "CODEPHIL";
    if (workingData.size() >= signature.size() &&
        std::memcmp(workingData.data(), signature.data(), signature.size()) != 0)
    {
        std::cout << "[!] Warning: 'CODEPHIL' signature not found\nFound: ";
        for (size_t i = 0; i < signature.size() && i < workingData.size(); ++i)
        {
            unsigned char c = workingData[i];
            if (std::isprint(c))
                std::cout << static_cast<char>(c);
            else
                std::cout << "\\x" << std::hex
                << std::setw(2) << std::setfill('0')
                << static_cast<int>(c);
        }
        std::cout << std::dec << "\n";
    }

    if (workingData.size() > signature.size())
        decryptedData.assign(workingData.begin() + static_cast<std::ptrdiff_t>(signature.size()),
            workingData.end());
    else
        decryptedData = std::move(workingData);

    return true;
}


int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "Usage: " << argv[0]
            << " <global-metadata.dat> <output_metadata.dat>\n";
        return 1;
    }

    const std::string inputPath = argv[1];
    const std::string outputPath = argv[2];

    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile)
    {
        std::cout << "[!] Cannot open input file: " << inputPath << "\n";
        return 1;
    }

    std::vector<unsigned char> encryptedData(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    std::cout << "Loaded " << encryptedData.size() << " bytes from "
        << inputPath << "\n";

    std::vector<unsigned char> decryptedData;
    if (!DecryptMetadata(encryptedData, decryptedData))
    {
        std::cout << "[!] Decryption failed\n";
        return 1;
    }

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile)
    {
        std::cout << "[!] Cannot create output file: " << outputPath << "\n";
        return 1;
    }

    outFile.write(reinterpret_cast<const char*>(decryptedData.data()),
        static_cast<std::streamsize>(decryptedData.size()));
    outFile.close();

    std::cout << "Decrypted " << decryptedData.size()
        << " bytes -> saved to " << outputPath << "\n";

    if (decryptedData.size() >= 4)
    {
        const uint32_t newMagic = ReadLE32(decryptedData.data());
        std::cout << "First 4 bytes of decrypted data: 0x"
            << std::hex << newMagic << std::dec << "\n";

        if (newMagic == 0xFAB11BAF)
            std::cout << "[SUCCEED] Valid IL2CPP metadata magic (AF 1B B1 FA)\n";
    }

    return 0;
}
