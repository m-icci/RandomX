#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include "../randomx.h"

// Helper function to convert hex string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Per Monero mining protocol, the 4-byte nonce is located at offset 39 in the block hashing blob.
// It is encoded in little-endian format.
const unsigned int NONCE_OFFSET = 39;

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <key_hex> <blob_hex> <nonce_int>" << std::endl;
        return 1;
    }

    std::string key_hex = argv[1];
    std::string blob_hex = argv[2];
    uint32_t nonce;
    try {
        nonce = std::stoul(argv[3]);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: Invalid nonce '" << argv[3] << "'. Please provide a valid integer." << std::endl;
        return 1;
    } catch (const std::out_of_range& e) {
        std::cerr << "Error: Nonce '" << argv[3] << "' is out of range." << std::endl;
        return 1;
    }

    std::vector<uint8_t> key = hex_to_bytes(key_hex);
    std::vector<uint8_t> blob = hex_to_bytes(blob_hex);

    // Apply nonce to blob
    if (blob.size() >= NONCE_OFFSET + 4) {
        blob[NONCE_OFFSET + 0] = (nonce >> 0) & 0xFF;
        blob[NONCE_OFFSET + 1] = (nonce >> 8) & 0xFF;
        blob[NONCE_OFFSET + 2] = (nonce >> 16) & 0xFF;
        blob[NONCE_OFFSET + 3] = (nonce >> 24) & 0xFF;
    } else {
        std::cerr << "Blob is too small" << std::endl;
        return 1;
    }

    randomx_flags flags = randomx_get_flags();
    randomx_cache *cache = randomx_alloc_cache(flags);
    if (cache == nullptr) {
        std::cerr << "Failed to allocate cache" << std::endl;
        return 1;
    }

    if (key.empty()) {
        std::cerr << "Error: Invalid key provided. Key cannot be empty." << std::endl;
        randomx_release_cache(cache);
        return 1;
    }

    randomx_init_cache(cache, key.data(), key.size());

    randomx_vm *vm = randomx_create_vm(flags, cache, nullptr);
    if (vm == nullptr) {
        std::cerr << "Failed to create VM" << std::endl;
        randomx_release_cache(cache);
        return 1;
    }

    uint8_t hash[RANDOMX_HASH_SIZE];
    randomx_calculate_hash(vm, blob.data(), blob.size(), hash);

    // Print hash
    for (int i = 0; i < RANDOMX_HASH_SIZE; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::endl;

    randomx_destroy_vm(vm);
    randomx_release_cache(cache);

    return 0;
}
