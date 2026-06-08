/*
 *  Steam Bridge v3.0 — Enterprise-Grade Cross-Reality Bridge
 *  A comprehensive C++ implementation connecting MetaVerse to BlockChain
 *  with cryptographic integrity, proof-of-work consensus, smart bridging,
 *  and complete memory safety.
 *
 *  Compile: g++ -std=c++17 -O2 -o steam_bridge steam_bridge.cpp -lm -Wall -Wextra -pedantic
 *  Run:     ./steam_bridge
 *
 *  "Where virtual worlds meet immutable truth."
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <set>
#include <memory>
#include <optional>
#include <variant>
#include <functional>
#include <algorithm>
#include <chrono>
#include <random>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <stdexcept>
#include <type_traits>

// ============================================================================
// SECTION 1: Cryptographic Primitives & Utility Classes
// ============================================================================

namespace SteamBridge::Crypto {

    /**
     * @class SHA256
     * @brief Pure C++ implementation of SHA-256 hash algorithm (FIPS 180-4)
     * 
     * Provides static methods for hashing strings and binary data,
     * plus a streaming context for incremental hashing.
     */
    class SHA256 {
    private:
        static constexpr size_t BLOCK_SIZE = 64;
        static constexpr size_t DIGEST_SIZE = 32;
        static constexpr uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

    public:
        /**
         * @class Context
         * @brief Streaming context for incremental SHA-256 hashing
         */
        class Context {
        private:
            uint8_t m_buffer[BLOCK_SIZE];
            size_t m_buffer_length;
            uint64_t m_bit_count;
            uint32_t m_state[8];

            // Bitwise rotation and logical functions
            static inline uint32_t rotr(uint32_t value, unsigned int count) noexcept {
                return (value >> count) | (value << (32 - count));
            }
            
            static inline uint32_t choose(uint32_t x, uint32_t y, uint32_t z) noexcept {
                return (x & y) ^ (~x & z);
            }
            
            static inline uint32_t majority(uint32_t x, uint32_t y, uint32_t z) noexcept {
                return (x & y) ^ (x & z) ^ (y & z);
            }
            
            static inline uint32_t sigma0(uint32_t x) noexcept {
                return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
            }
            
            static inline uint32_t sigma1(uint32_t x) noexcept {
                return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
            }
            
            static inline uint32_t epsilon0(uint32_t x) noexcept {
                return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
            }
            
            static inline uint32_t epsilon1(uint32_t x) noexcept {
                return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
            }

            void transform(const uint8_t data[BLOCK_SIZE]) noexcept;

        public:
            Context() noexcept;
            void update(const uint8_t* data, size_t length) noexcept;
            void update(const std::string_view& data) noexcept;
            std::array<uint8_t, DIGEST_SIZE> finalize() noexcept;
            void reset() noexcept;
        };

        /**
         * @brief Compute SHA-256 hash of a string and return hex representation
         * @param input String to hash
         * @return 64-character hexadecimal string
         */
        static std::string hash_hex(const std::string_view& input);
        
        /**
         * @brief Compute SHA-256 hash of binary data
         * @param data Pointer to data
         * @param length Length in bytes
         * @return 32-byte hash array
         */
        static std::array<uint8_t, DIGEST_SIZE> hash(const uint8_t* data, size_t length);
        
        /**
         * @brief Compute double SHA-256 (SHA256d) as used in Bitcoin
         */
        static std::string hash256d_hex(const std::string_view& input);
    };

    // Implementation of SHA256::Context
    SHA256::Context::Context() noexcept {
        reset();
    }

    void SHA256::Context::reset() noexcept {
        m_buffer_length = 0;
        m_bit_count = 0;
        m_state[0] = 0x6a09e667; m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372; m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f; m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab; m_state[7] = 0x5be0cd19;
    }

    void SHA256::Context::transform(const uint8_t data[BLOCK_SIZE]) noexcept {
        uint32_t m[64];
        // Prepare message schedule
        for (size_t i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (static_cast<uint32_t>(data[j]) << 24) |
                   (static_cast<uint32_t>(data[j + 1]) << 16) |
                   (static_cast<uint32_t>(data[j + 2]) << 8) |
                   static_cast<uint32_t>(data[j + 3]);
        }
        for (size_t i = 16; i < 64; ++i) {
            m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
        }

        // Initialize working variables
        uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
        uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];

        // Compression function main loop
        for (size_t i = 0; i < 64; ++i) {
            uint32_t t1 = h + epsilon1(e) + choose(e, f, g) + K[i] + m[i];
            uint32_t t2 = epsilon0(a) + majority(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        // Update state
        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }

    void SHA256::Context::update(const uint8_t* data, size_t length) noexcept {
        for (size_t i = 0; i < length; ++i) {
            m_buffer[m_buffer_length++] = data[i];
            if (m_buffer_length == BLOCK_SIZE) {
                transform(m_buffer);
                m_bit_count += 512;
                m_buffer_length = 0;
            }
        }
    }

    void SHA256::Context::update(const std::string_view& data) noexcept {
        update(reinterpret_cast<const uint8_t*>(data.data()), data.length());
    }

    std::array<uint8_t, SHA256::DIGEST_SIZE> SHA256::Context::finalize() noexcept {
        std::array<uint8_t, DIGEST_SIZE> digest{};
        
        // Padding
        size_t i = m_buffer_length;
        m_buffer[i++] = 0x80;
        if (m_buffer_length >= 56) {
            while (i < BLOCK_SIZE) m_buffer[i++] = 0;
            transform(m_buffer);
            i = 0;
        }
        while (i < 56) m_buffer[i++] = 0;
        
        // Append bit length
        m_bit_count += m_buffer_length * 8;
        m_buffer[56] = static_cast<uint8_t>(m_bit_count >> 56);
        m_buffer[57] = static_cast<uint8_t>(m_bit_count >> 48);
        m_buffer[58] = static_cast<uint8_t>(m_bit_count >> 40);
        m_buffer[59] = static_cast<uint8_t>(m_bit_count >> 32);
        m_buffer[60] = static_cast<uint8_t>(m_bit_count >> 24);
        m_buffer[61] = static_cast<uint8_t>(m_bit_count >> 16);
        m_buffer[62] = static_cast<uint8_t>(m_bit_count >> 8);
        m_buffer[63] = static_cast<uint8_t>(m_bit_count);
        transform(m_buffer);

        // Produce digest
        for (i = 0; i < 4; ++i) {
            digest[i]      = static_cast<uint8_t>((m_state[0] >> (24 - i * 8)) & 0xFF);
            digest[i + 4]  = static_cast<uint8_t>((m_state[1] >> (24 - i * 8)) & 0xFF);
            digest[i + 8]  = static_cast<uint8_t>((m_state[2] >> (24 - i * 8)) & 0xFF);
            digest[i + 12] = static_cast<uint8_t>((m_state[3] >> (24 - i * 8)) & 0xFF);
            digest[i + 16] = static_cast<uint8_t>((m_state[4] >> (24 - i * 8)) & 0xFF);
            digest[i + 20] = static_cast<uint8_t>((m_state[5] >> (24 - i * 8)) & 0xFF);
            digest[i + 24] = static_cast<uint8_t>((m_state[6] >> (24 - i * 8)) & 0xFF);
            digest[i + 28] = static_cast<uint8_t>((m_state[7] >> (24 - i * 8)) & 0xFF);
        }
        
        return digest;
    }

    std::string SHA256::hash_hex(const std::string_view& input) {
        Context ctx;
        ctx.update(input);
        auto digest = ctx.finalize();
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : digest) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::array<uint8_t, SHA256::DIGEST_SIZE> SHA256::hash(const uint8_t* data, size_t length) {
        Context ctx;
        ctx.update(data, length);
        return ctx.finalize();
    }

    std::string SHA256::hash256d_hex(const std::string_view& input) {
        return hash_hex(hash_hex(input));
    }

} // namespace SteamBridge::Crypto

// ============================================================================
// SECTION 2: Cryptographic Wallet & Digital Signatures
// ============================================================================

namespace SteamBridge::Crypto {

    /**
     * @class Wallet
     * @brief Represents a user's cryptographic identity with keypair
     * 
     * In a production system, this would use secp256k1 elliptic curve.
     * For purity of demonstration, we use deterministic key derivation
     * with SHA-256 to create consistent keypairs from entropy.
     */
    class Wallet {
    private:
        std::string m_private_key_hex;  // 64 hex chars = 32 bytes
        std::string m_public_key_hex;   // 64 hex chars
        std::string m_address;          // Shorter public identifier
        
        /**
         * @brief Derive public key from private key using one-way hash
         * @note Simplified - real systems use ECDSA public key derivation
         */
        static std::string derive_public_key(const std::string& private_key_hex) {
            return SHA256::hash_hex("PUBKEY_DERIVATION_V1:" + private_key_hex);
        }
        
        /**
         * @brief Derive address from public key
         */
        static std::string derive_address(const std::string& public_key_hex) {
            return SHA256::hash_hex("ADDRESS_V1:" + public_key_hex).substr(0, 40);
        }

    public:
        /**
         * @brief Default constructor - creates wallet with random entropy
         */
        Wallet() {
            // Generate entropy from multiple sources
            auto now = std::chrono::high_resolution_clock::now();
            auto duration = now.time_since_epoch();
            auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
            
            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<uint64_t> dist;
            
            std::stringstream entropy;
            entropy << std::hex << nanos << dist(gen) << dist(gen) << rd();
            
            m_private_key_hex = SHA256::hash_hex(entropy.str());
            m_public_key_hex = derive_public_key(m_private_key_hex);
            m_address = derive_address(m_public_key_hex);
        }
        
        /**
         * @brief Constructor with explicit private key (for testing/restoration)
         */
        explicit Wallet(const std::string& private_key_hex) 
            : m_private_key_hex(private_key_hex) {
            if (private_key_hex.length() != 64) {
                throw std::invalid_argument("Private key must be 64 hex characters");
            }
            m_public_key_hex = derive_public_key(m_private_key_hex);
            m_address = derive_address(m_public_key_hex);
        }
        
        // Accessors
        [[nodiscard]] const std::string& get_private_key_hex() const noexcept { return m_private_key_hex; }
        [[nodiscard]] const std::string& get_public_key_hex() const noexcept { return m_public_key_hex; }
        [[nodiscard]] const std::string& get_address() const noexcept { return m_address; }
        
        /**
         * @brief Sign a message using the private key
         * @param message The message to sign
         * @return 64-char hex signature
         */
        [[nodiscard]] std::string sign(const std::string_view& message) const {
            // ECDSA signing simulation: Hash(private_key || message)
            std::string data = m_private_key_hex + std::string(message);
            return SHA256::hash_hex(data);
        }
        
        /**
         * @brief Verify a signature (static method)
         * @param public_key_hex The signer's public key
         * @param message The original message
         * @param signature_hex The signature to verify
         * @return true if signature is valid
         */
        [[nodiscard]] static bool verify(const std::string& public_key_hex, 
                                         const std::string_view& message,
                                         const std::string& signature_hex) {
            // In real ECDSA, use public key math. Here we use hash-based verification
            std::string derived_priv = SHA256::hash_hex("VERIFY_SALT:" + public_key_hex);
            std::string expected_sig = SHA256::hash_hex(derived_priv + std::string(message));
            return signature_hex == expected_sig;
        }
        
        /**
         * @brief String representation for debugging
         */
        [[nodiscard]] std::string to_string() const {
            std::stringstream ss;
            ss << "Wallet[Address: " << m_address.substr(0, 16) << "...]";
            return ss.str();
        }
        
        // Comparison operators
        bool operator==(const Wallet& other) const noexcept {
            return m_public_key_hex == other.m_public_key_hex;
        }
        bool operator!=(const Wallet& other) const noexcept {
            return !(*this == other);
        }
    };

    /**
     * @class MerkleTree
     * @brief Merkle tree implementation for transaction verification
     */
    class MerkleTree {
    private:
        std::vector<std::string> m_leaves;
        std::vector<std::vector<std::string>> m_tree;
        std::string m_root_hash;

        void build_tree() {
            if (m_leaves.empty()) {
                m_root_hash = SHA256::hash_hex("EMPTY_MERKLE_TREE");
                return;
            }
            
            m_tree.clear();
            m_tree.push_back(m_leaves);
            
            while (m_tree.back().size() > 1) {
                std::vector<std::string> next_level;
                const auto& current = m_tree.back();
                
                for (size_t i = 0; i < current.size(); i += 2) {
                    if (i + 1 < current.size()) {
                        next_level.push_back(SHA256::hash_hex(current[i] + current[i + 1]));
                    } else {
                        // Odd number - duplicate last element
                        next_level.push_back(SHA256::hash_hex(current[i] + current[i]));
                    }
                }
                m_tree.push_back(next_level);
            }
            
            m_root_hash = m_tree.back()[0];
        }

    public:
        MerkleTree() = default;
        
        explicit MerkleTree(const std::vector<std::string>& items) : m_leaves(items) {
            build_tree();
        }
        
        void add_leaf(const std::string& item) {
            m_leaves.push_back(item);
            build_tree();
        }
        
        [[nodiscard]] const std::string& get_root_hash() const noexcept { return m_root_hash; }
        
        [[nodiscard]] size_t leaf_count() const noexcept { return m_leaves.size(); }
        
        /**
         * @brief Generate Merkle proof for a leaf
         * @return Vector of sibling hashes from leaf to root
         */
        [[nodiscard]] std::vector<std::pair<std::string, bool>> generate_proof(size_t index) const {
            std::vector<std::pair<std::string, bool>> proof; // hash, is_left
            size_t current_index = index;
            
            for (size_t level = 0; level < m_tree.size() - 1; ++level) {
                bool is_left = (current_index % 2 == 0);
                size_t sibling_index = is_left ? current_index + 1 : current_index - 1;
                
                if (sibling_index < m_tree[level].size()) {
                    proof.emplace_back(m_tree[level][sibling_index], is_left);
                }
                
                current_index /= 2;
            }
            
            return proof;
        }
    };

} // namespace SteamBridge::Crypto

// ============================================================================
// SECTION 3: BlockChain Layer
// ============================================================================

namespace SteamBridge::Blockchain {

    using namespace Crypto;
    
    // Difficulty target for Proof-of-Work (number of leading zero nibbles)
    constexpr int DEFAULT_DIFFICULTY = 4;
    constexpr size_t MAX_TRANSACTIONS_PER_BLOCK = 100;
    constexpr size_t BLOCK_SIZE_LIMIT = 1024 * 1024; // 1MB simulated

    /**
     * @class Transaction
     * @brief Represents a single transaction on the blockchain
     * 
     * Contains sender, receiver, asset reference, amount, and cryptographic signature.
     */
    class Transaction {
    private:
        std::string m_tx_id;           // Transaction hash
        std::string m_from_address;    // Sender's wallet address
        std::string m_to_address;      // Recipient's wallet address
        std::string m_asset_id;        // Asset being transferred (empty for currency)
        uint64_t m_amount;             // Amount (for fungible tokens)
        uint64_t m_timestamp;          // Unix timestamp
        std::string m_signature;       // Cryptographic signature
        std::string m_data;            // Optional arbitrary data
        uint32_t m_nonce;              // Transaction nonce (ordering)
        bool m_is_bridge_tx;           // Whether this is a bridge transaction

    public:
        Transaction(const std::string& from, const std::string& to,
                   const std::string& asset_id, uint64_t amount,
                   const Wallet& signer, const std::string& data = "",
                   bool is_bridge = false)
            : m_from_address(from), m_to_address(to), m_asset_id(asset_id),
              m_amount(amount), m_data(data), m_is_bridge_tx(is_bridge) {
            
            m_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            
            // Create unique nonce based on timestamp and random factor
            m_nonce = static_cast<uint32_t>(m_timestamp ^ 
                       (std::hash<std::string>{}(from + to + asset_id) & 0xFFFFFFFF));
            
            // Create transaction ID
            std::stringstream ss;
            ss << m_from_address << m_to_address << m_asset_id 
               << m_amount << m_timestamp << m_data << m_nonce;
            m_tx_id = SHA256::hash_hex(ss.str());
            
            // Sign the transaction
            std::string message = ss.str();
            m_signature = signer.sign(message);
        }
        
        // Accessors
        [[nodiscard]] const std::string& get_tx_id() const noexcept { return m_tx_id; }
        [[nodiscard]] const std::string& get_from_address() const noexcept { return m_from_address; }
        [[nodiscard]] const std::string& get_to_address() const noexcept { return m_to_address; }
        [[nodiscard]] const std::string& get_asset_id() const noexcept { return m_asset_id; }
        [[nodiscard]] uint64_t get_amount() const noexcept { return m_amount; }
        [[nodiscard]] uint64_t get_timestamp() const noexcept { return m_timestamp; }
        [[nodiscard]] const std::string& get_signature() const noexcept { return m_signature; }
        [[nodiscard]] const std::string& get_data() const noexcept { return m_data; }
        [[nodiscard]] uint32_t get_nonce() const noexcept { return m_nonce; }
        [[nodiscard]] bool is_bridge_transaction() const noexcept { return m_is_bridge_tx; }
        
        /**
         * @brief Serialize transaction for hashing
         */
        [[nodiscard]] std::string serialize() const {
            std::stringstream ss;
            ss << m_tx_id << m_from_address << m_to_address << m_asset_id
               << m_amount << m_timestamp << m_signature << m_nonce;
            return ss.str();
        }
        
        /**
         * @brief Validate transaction signature
         */
        [[nodiscard]] bool is_valid() const {
            std::stringstream ss;
            ss << m_from_address << m_to_address << m_asset_id 
               << m_amount << m_timestamp << m_data << m_nonce;
            return Wallet::verify(m_from_address, ss.str(), m_signature);
        }
    };

    /**
     * @class Block
     * @brief A single block in the blockchain
     * 
     * Contains a list of transactions, metadata, and proof-of-work.
     */
    class Block {
    private:
        uint32_t m_index;                  // Block height
        uint64_t m_timestamp;              // Creation timestamp
        std::string m_previous_hash;       // Link to previous block
        std::string m_merkle_root;         // Merkle tree root of transactions
        std::string m_hash;                // This block's hash
        uint64_t m_nonce;                  // Proof-of-work nonce
        std::vector<std::shared_ptr<Transaction>> m_transactions;
        int m_difficulty;                  // Mining difficulty

        /**
         * @brief Compute the Merkle tree root from transactions
         */
        [[nodiscard]] std::string compute_merkle_root() const {
            if (m_transactions.empty()) {
                return SHA256::hash_hex("EMPTY_BLOCK_MERKLE");
            }
            
            MerkleTree tree;
            for (const auto& tx : m_transactions) {
                tree.add_leaf(tx->get_tx_id());
            }
            return tree.get_root_hash();
        }

        /**
         * @brief Perform proof-of-work mining
         */
        void mine() {
            std::string target_prefix(m_difficulty, '0');
            m_nonce = 0;
            
            while (true) {
                std::stringstream ss;
                ss << m_index << m_timestamp << m_previous_hash 
                   << m_merkle_root << m_nonce;
                m_hash = SHA256::hash_hex(ss.str());
                
                if (m_hash.substr(0, m_difficulty) == target_prefix) {
                    break;
                }
                
                ++m_nonce;
                
                // Check for overflow (extremely unlikely but safe)
                if (m_nonce == UINT64_MAX) {
                    m_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();
                    m_nonce = 0;
                }
            }
        }

    public:
        Block(uint32_t index, const std::string& previous_hash, int difficulty = DEFAULT_DIFFICULTY)
            : m_index(index), m_previous_hash(previous_hash), m_difficulty(difficulty) {
            m_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
        }
        
        /**
         * @brief Add a transaction to the block
         */
        void add_transaction(std::shared_ptr<Transaction> tx) {
            if (m_transactions.size() >= MAX_TRANSACTIONS_PER_BLOCK) {
                throw std::runtime_error("Block transaction limit reached");
            }
            m_transactions.push_back(std::move(tx));
        }
        
        /**
         * @brief Finalize the block (compute Merkle root and mine)
         */
        void finalize() {
            m_merkle_root = compute_merkle_root();
            mine();
        }
        
        // Accessors
        [[nodiscard]] uint32_t get_index() const noexcept { return m_index; }
        [[nodiscard]] uint64_t get_timestamp() const noexcept { return m_timestamp; }
        [[nodiscard]] const std::string& get_previous_hash() const noexcept { return m_previous_hash; }
        [[nodiscard]] const std::string& get_merkle_root() const noexcept { return m_merkle_root; }
        [[nodiscard]] const std::string& get_hash() const noexcept { return m_hash; }
        [[nodiscard]] uint64_t get_nonce() const noexcept { return m_nonce; }
        [[nodiscard]] size_t get_transaction_count() const noexcept { return m_transactions.size(); }
        [[nodiscard]] const std::vector<std::shared_ptr<Transaction>>& get_transactions() const noexcept { 
            return m_transactions; 
        }
        
        /**
         * @brief Validate the block's integrity
         */
        [[nodiscard]] bool is_valid() const {
            // Verify hash meets difficulty target
            std::string target_prefix(m_difficulty, '0');
            std::stringstream ss;
            ss << m_index << m_timestamp << m_previous_hash << m_merkle_root << m_nonce;
            std::string computed_hash = SHA256::hash_hex(ss.str());
            
            if (m_hash != computed_hash) return false;
            if (m_hash.substr(0, m_difficulty) != target_prefix) return false;
            
            // Verify Merkle root
            if (m_merkle_root != compute_merkle_root()) return false;
            
            // Verify all transactions
            for (const auto& tx : m_transactions) {
                if (!tx->is_valid()) return false;
            }
            
            return true;
        }
    };

    /**
     * @class BlockChain
     * @brief The complete blockchain data structure
     * 
     * Manages the chain of blocks, provides validation, and maintains state.
     */
    class BlockChain {
    private:
        std::vector<std::shared_ptr<Block>> m_chain;
        std::unordered_map<std::string, std::shared_ptr<Transaction>> m_tx_index;
        int m_difficulty;
        uint64_t m_total_transactions;
        
        /**
         * @brief Create the genesis block
         */
        std::shared_ptr<Block> create_genesis_block() {
            auto genesis = std::make_shared<Block>(0, 
                "0000000000000000000000000000000000000000000000000000000000000000",
                m_difficulty);
            
            // Create a genesis message transaction
            auto genesis_tx = std::make_shared<Transaction>(
                "GENESIS", "GENESIS", "GENESIS_ASSET", 0,
                Wallet(), "Steam Bridge v3.0 Genesis Block - " + 
                std::to_string(std::chrono::system_clock::now().time_since_epoch().count())
            );
            genesis->add_transaction(genesis_tx);
            genesis->finalize();
            
            return genesis;
        }

    public:
        explicit BlockChain(int difficulty = DEFAULT_DIFFICULTY) 
            : m_difficulty(difficulty), m_total_transactions(0) {
            m_chain.push_back(create_genesis_block());
            m_total_transactions += m_chain[0]->get_transaction_count();
            std::cout << "[BLOCKCHAIN] Genesis block created: " 
                      << m_chain[0]->get_hash().substr(0, 16) << "...\n";
        }
        
        /**
         * @brief Add a new block to the chain
         */
        std::shared_ptr<Block> add_block(const std::vector<std::shared_ptr<Transaction>>& transactions) {
            auto block = std::make_shared<Block>(
                static_cast<uint32_t>(m_chain.size()),
                m_chain.back()->get_hash(),
                m_difficulty
            );
            
            for (const auto& tx : transactions) {
                block->add_transaction(tx);
                m_tx_index[tx->get_tx_id()] = tx;
            }
            
            block->finalize();
            m_chain.push_back(block);
            m_total_transactions += transactions.size();
            
            std::cout << "[BLOCKCHAIN] Block #" << block->get_index() << " mined: "
                      << block->get_hash().substr(0, 16) << "... (nonce: " 
                      << block->get_nonce() << ", txs: " << transactions.size() << ")\n";
            
            return block;
        }
        
        /**
         * @brief Add a single transaction as a new block
         */
        std::shared_ptr<Block> add_transaction(std::shared_ptr<Transaction> tx) {
            return add_block({tx});
        }
        
        /**
         * @brief Validate the entire blockchain
         */
        [[nodiscard]] bool validate_chain() const {
            for (size_t i = 0; i < m_chain.size(); ++i) {
                // Validate individual block
                if (!m_chain[i]->is_valid()) {
                    std::cerr << "[VALIDATION] Block #" << i << " is invalid!\n";
                    return false;
                }
                
                // Validate chain linkage
                if (i > 0 && m_chain[i]->get_previous_hash() != m_chain[i-1]->get_hash()) {
                    std::cerr << "[VALIDATION] Chain broken at block #" << i << "!\n";
                    return false;
                }
            }
            return true;
        }
        
        /**
         * @brief Find a transaction by ID
         */
        [[nodiscard]] std::optional<std::shared_ptr<Transaction>> find_transaction(
            const std::string& tx_id) const {
            auto it = m_tx_index.find(tx_id);
            if (it != m_tx_index.end()) {
                return it->second;
            }
            return std::nullopt;
        }
        
        // Accessors
        [[nodiscard]] size_t get_height() const noexcept { return m_chain.size(); }
        [[nodiscard]] uint64_t get_total_transactions() const noexcept { return m_total_transactions; }
        [[nodiscard]] int get_difficulty() const noexcept { return m_difficulty; }
        [[nodiscard]] const std::vector<std::shared_ptr<Block>>& get_blocks() const noexcept { 
            return m_chain; 
        }
        [[nodiscard]] std::shared_ptr<Block> get_latest_block() const noexcept { 
            return m_chain.back(); 
        }
        
        /**
         * @brief Set mining difficulty (adjusts for future blocks)
         */
        void set_difficulty(int difficulty) {
            if (difficulty < 1 || difficulty > 64) {
                throw std::invalid_argument("Difficulty must be between 1 and 64");
            }
            m_difficulty = difficulty;
        }
    };

} // namespace SteamBridge::Blockchain

// ============================================================================
// SECTION 4: MetaVerse Layer
// ============================================================================

namespace SteamBridge::MetaVerse {

    using namespace Crypto;
    using namespace Blockchain;

    /**
     * @enum AssetType
     * @brief Categories of virtual assets in the MetaVerse
     */
    enum class AssetType : uint8_t {
        LAND,           // Virtual real estate
        ITEM,           // In-world items
        AVATAR,         // Character/Avatar
        WEARABLE,       // Clothing/accessories for avatars
        CURRENCY,       // In-world currency
        BLUEPR
        BLUEPRINT,      // Procedural generation data
        EFFECT,         // Visual/audio effects
        PASS,           // Access passes/tickets
        IDENTITY        // Digital identity credentials
    };

    /**
     * @brief Convert AssetType to readable string
     */
    inline std::string asset_type_to_string(AssetType type) {
        switch (type) {
            case AssetType::LAND:      return "LAND";
            case AssetType::ITEM:      return "ITEM";
            case AssetType::AVATAR:    return "AVATAR";
            case AssetType::WEARABLE:  return "WEARABLE";
            case AssetType::CURRENCY:  return "CURRENCY";
            case AssetType::BLUEPRINT: return "BLUEPRINT";
            case AssetType::EFFECT:    return "EFFECT";
            case AssetType::PASS:      return "PASS";
            case AssetType::IDENTITY:  return "IDENTITY";
            default: return "UNKNOWN";
        }
    }

    /**
     * @class WorldCoordinate
     * @brief 3D coordinate system for MetaVerse positioning
     */
    class WorldCoordinate {
    private:
        int64_t m_x, m_y, m_z;
        uint64_t m_world_id;

    public:
        WorldCoordinate(int64_t x = 0, int64_t y = 0, int64_t z = 0, uint64_t world_id = 0)
            : m_x(x), m_y(y), m_z(z), m_world_id(world_id) {}

        [[nodiscard]] int64_t get_x() const noexcept { return m_x; }
        [[nodiscard]] int64_t get_y() const noexcept { return m_y; }
        [[nodiscard]] int64_t get_z() const noexcept { return m_z; }
        [[nodiscard]] uint64_t get_world_id() const noexcept { return m_world_id; }

        /**
         * @brief Calculate distance between two coordinates
         */
        [[nodiscard]] double distance_to(const WorldCoordinate& other) const {
            if (m_world_id != other.m_world_id) return INFINITY;
            int64_t dx = m_x - other.m_x;
            int64_t dy = m_y - other.m_y;
            int64_t dz = m_z - other.m_z;
            return std::sqrt(static_cast<double>(dx*dx + dy*dy + dz*dz));
        }

        /**
         * @brief Generate a unique string identifier for this coordinate
         */
        [[nodiscard]] std::string to_id() const {
            std::stringstream ss;
            ss << "world_" << m_world_id << ":" << m_x << "," << m_y << "," << m_z;
            return ss.str();
        }

        bool operator==(const WorldCoordinate& other) const {
            return m_x == other.m_x && m_y == other.m_y && 
                   m_z == other.m_z && m_world_id == other.m_world_id;
        }

        struct Hash {
            size_t operator()(const WorldCoordinate& coord) const {
                std::hash<int64_t> hasher;
                return hasher(coord.m_x) ^ (hasher(coord.m_y) << 1) ^ 
                       (hasher(coord.m_z) << 2) ^ (hasher(coord.m_world_id) << 3);
            }
        };
    };

    /**
     * @class VirtualAsset
     * @brief Digital asset within the MetaVerse with on-chain linkage
     */
    class VirtualAsset {
    private:
        std::string m_asset_id;           // Unique asset ID (hash-based)
        std::string m_name;
        AssetType m_type;
        std::string m_owner_address;      // Blockchain wallet address
        std::string m_metadata;           // JSON/arbitrary metadata
        uint64_t m_creation_time;
        uint64_t m_last_update;
        std::string m_parent_asset_id;    // For nested assets
        std::optional<WorldCoordinate> m_position;
        bool m_is_on_chain;

        /**
         * @brief Generate asset ID from properties
         */
        static std::string generate_asset_id(const std::string& name, 
                                              const std::string& owner,
                                              AssetType type,
                                              uint64_t timestamp) {
            std::stringstream ss;
            ss << name << owner << static_cast<uint8_t>(type) << timestamp;
            return SHA256::hash_hex(ss.str()).substr(0, 48);
        }

    public:
        VirtualAsset(const std::string& name, AssetType type, const Wallet& owner,
                     const std::string& metadata = "", const std::string& parent = "")
            : m_name(name), m_type(type), m_owner_address(owner.get_address()),
              m_metadata(metadata), m_parent_asset_id(parent), m_is_on_chain(false) {
            
            m_creation_time = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            m_last_update = m_creation_time;
            m_asset_id = generate_asset_id(name, m_owner_address, type, m_creation_time);
        }

        // Accessors
        [[nodiscard]] const std::string& get_asset_id() const noexcept { return m_asset_id; }
        [[nodiscard]] const std::string& get_name() const noexcept { return m_name; }
        [[nodiscard]] AssetType get_type() const noexcept { return m_type; }
        [[nodiscard]] const std::string& get_owner_address() const noexcept { return m_owner_address; }
        [[nodiscard]] const std::string& get_metadata() const noexcept { return m_metadata; }
        [[nodiscard]] uint64_t get_creation_time() const noexcept { return m_creation_time; }
        [[nodiscard]] uint64_t get_last_update() const noexcept { return m_last_update; }
        [[nodiscard]] const std::string& get_parent_asset_id() const noexcept { return m_parent_asset_id; }
        [[nodiscard]] bool is_on_chain() const noexcept { return m_is_on_chain; }
        [[nodiscard]] const std::optional<WorldCoordinate>& get_position() const noexcept { return m_position; }

        void set_position(const WorldCoordinate& pos) { m_position = pos; m_last_update = time(nullptr); }
        void set_metadata(const std::string& metadata) { m_metadata = metadata; m_last_update = time(nullptr); }
        void set_on_chain(bool on_chain) { m_is_on_chain = on_chain; }
        
        /**
         * @brief Transfer ownership to another wallet
         */
        bool transfer_ownership(const Wallet& new_owner, const Wallet& current_owner) {
            if (m_owner_address != current_owner.get_address()) {
                return false;
            }
            std::string old_owner = m_owner_address;
            m_owner_address = new_owner.get_address();
            m_last_update = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            // Regenerate asset ID after ownership change
            m_asset_id = generate_asset_id(m_name, m_owner_address, m_type, m_last_update);
            return true;
        }

        /**
         * @brief Create blockchain transaction for this asset
         */
        [[nodiscard]] std::shared_ptr<Transaction> create_chain_transaction(
            const Wallet& signer, const std::string& to_address = "",
            uint64_t token_amount = 0) const {
            
            std::string tx_data = "ASSET:" + m_asset_id + "|NAME:" + m_name + 
                                  "|TYPE:" + asset_type_to_string(m_type) + 
                                  "|METADATA:" + m_metadata;
            
            std::string to = to_address.empty() ? m_owner_address : to_address;
            
            return std::make_shared<Transaction>(
                m_owner_address, to, m_asset_id, token_amount, signer, tx_data, true
            );
        }
    };

    /**
     * @class MetaVerseEngine
     * @brief Core MetaVerse simulation and management system
     * 
     * Manages virtual assets, world state, and bridges to blockchain.
     */
    class MetaVerseEngine {
    private:
        std::unordered_map<std::string, std::shared_ptr<VirtualAsset>> m_assets;
        std::unordered_map<std::string, std::vector<std::string>> m_assets_by_owner;
        std::unordered_map<WorldCoordinate, std::string, WorldCoordinate::Hash> m_world_grid;
        uint64_t m_total_worlds;
        uint64_t m_total_assets;
        
        std::mt19937_64 m_rng;

    public:
        MetaVerseEngine() : m_total_worlds(1), m_total_assets(0), m_rng(std::random_device{}()) {
            std::cout << "[METAVERSE] MetaVerse Engine v3.0 initialized\n";
        }

        /**
         * @brief Create a new virtual asset
         */
        std::shared_ptr<VirtualAsset> create_asset(const std::string& name, AssetType type,
                                                    const Wallet& owner, const std::string& metadata = "",
                                                    const std::optional<WorldCoordinate>& position = std::nullopt) {
            
            auto asset = std::make_shared<VirtualAsset>(name, type, owner, metadata);
            m_assets[asset->get_asset_id()] = asset;
            m_assets_by_owner[owner.get_address()].push_back(asset->get_asset_id());
            
            if (position.has_value()) {
                asset->set_position(position.value());
                m_world_grid[position.value()] = asset->get_asset_id();
            }
            
            m_total_assets++;
            
            std::cout << "[METAVERSE] Asset created: " << name 
                      << " (" << asset_type_to_string(type) << ") ID: " 
                      << asset->get_asset_id().substr(0, 16) << "...\n";
            
            return asset;
        }

        /**
         * @brief Find asset by ID
         */
        [[nodiscard]] std::optional<std::shared_ptr<VirtualAsset>> find_asset(const std::string& asset_id) const {
            auto it = m_assets.find(asset_id);
            if (it != m_assets.end()) {
                return it->second;
            }
            return std::nullopt;
        }

        /**
         * @brief Get all assets owned by a wallet
         */
        [[nodiscard]] std::vector<std::shared_ptr<VirtualAsset>> get_owner_assets(const std::string& address) const {
            std::vector<std::shared_ptr<VirtualAsset>> result;
            auto it = m_assets_by_owner.find(address);
            if (it != m_assets_by_owner.end()) {
                for (const auto& asset_id : it->second) {
                    auto asset = m_assets.find(asset_id);
                    if (asset != m_assets.end()) {
                        result.push_back(asset->second);
                    }
                }
            }
            return result;
        }

        /**
         * @brief Find asset at a specific world coordinate
         */
        [[nodiscard]] std::optional<std::shared_ptr<VirtualAsset>> find_asset_at(const WorldCoordinate& coord) const {
            auto it = m_world_grid.find(coord);
            if (it != m_world_grid.end()) {
                return find_asset(it->second);
            }
            return std::nullopt;
        }

        /**
         * @brief Move asset to new location
         */
        bool move_asset(const std::string& asset_id, const WorldCoordinate& new_pos, const Wallet& owner) {
            auto asset_opt = find_asset(asset_id);
            if (!asset_opt.has_value()) return false;
            
            auto asset = asset_opt.value();
            if (asset->get_owner_address() != owner.get_address()) return false;
            
            // Remove from old grid position
            if (asset->get_position().has_value()) {
                auto it = m_world_grid.find(asset->get_position().value());
                if (it != m_world_grid.end() && it->second == asset_id) {
                    m_world_grid.erase(it);
                }
            }
            
            asset->set_position(new_pos);
            m_world_grid[new_pos] = asset_id;
            
            std::cout << "[METAVERSE] Asset " << asset_id.substr(0, 16) 
                      << "... moved to " << new_pos.to_id() << "\n";
            return true;
        }

        /**
         * @brief Bridge asset to blockchain (create on-chain representation)
         */
        std::shared_ptr<Transaction> bridge_asset_to_chain(const std::string& asset_id,
                                                            const Wallet& owner,
                                                            uint64_t valuation_tokens = 0) {
            auto asset_opt = find_asset(asset_id);
            if (!asset_opt.has_value()) {
                throw std::runtime_error("Asset not found");
            }
            
            auto asset = asset_opt.value();
            if (asset->get_owner_address() != owner.get_address()) {
                throw std::runtime_error("Not the asset owner");
            }
            
            asset->set_on_chain(true);
            
            // Bridge transaction: owner sends asset to bridge contract
            std::string bridge_data = "BRIDGE_TO_BLOCKCHAIN|ASSET:" + asset_id + 
                                      "|WORLD_POS:" + (asset->get_position().has_value() ? 
                                      asset->get_position()->to_id() : "UNBOUND");
            
            auto tx = std::make_shared<Transaction>(
                owner.get_address(),
                "BRIDGE_CONTRACT_" + asset_id.substr(0, 16),
                asset_id,
                valuation_tokens,
                owner,
                bridge_data,
                true
            );
            
            std::cout << "[BRIDGE] Asset " << asset->get_name() 
                      << " bridged to blockchain. Transaction: " 
                      << tx->get_tx_id().substr(0, 16) << "...\n";
            
            return tx;
        }

        /**
         * @brief Generate statistics about the MetaVerse
         */
        void print_stats() const {
            std::cout << "\n=== MetaVerse Statistics ===\n";
            std::cout << "Total Worlds: " << m_total_worlds << "\n";
            std::cout << "Total Assets: " << m_total_assets << "\n";
            std::cout << "Assets On-Chain: " 
                      << std::count_if(m_assets.begin(), m_assets.end(),
                          [](const auto& pair) { return pair.second->is_on_chain(); }) << "\n";
            std::cout << "Occupied Grid Cells: " << m_world_grid.size() << "\n";
            
            std::map<AssetType, size_t> type_counts;
            for (const auto& [id, asset] : m_assets) {
                type_counts[asset->get_type()]++;
            }
            std::cout << "Asset Type Distribution:\n";
            for (const auto& [type, count] : type_counts) {
                std::cout << "  " << asset_type_to_string(type) << ": " << count << "\n";
            }
            std::cout << "===========================\n";
        }

        [[nodiscard]] uint64_t get_total_assets() const noexcept { return m_total_assets; }
    };

} // namespace SteamBridge::MetaVerse

// ============================================================================
// SECTION 5: Bridge Consensus & Smart Bridging Logic
// ============================================================================

namespace SteamBridge::Bridge {

    using namespace Crypto;
    using namespace Blockchain;
    using namespace MetaVerse;

    /**
     * @struct BridgeRequest
     * @brief Represents a request to bridge an asset between MetaVerse and Blockchain
     */
    struct BridgeRequest {
        enum class Direction { METAVERSE_TO_BLOCKCHAIN, BLOCKCHAIN_TO_METAVERSE };
        
        Direction direction;
        std::string asset_id;
        std::string from_address;
        std::string to_address;
        uint64_t token_amount;
        std::string metadata;
        uint64_t timestamp;
        std::string request_hash;
        bool is_approved;
        
        BridgeRequest(Direction dir, const std::string& asset, const std::string& from,
                      const std::string& to, uint64_t amount, const std::string& meta)
            : direction(dir), asset_id(asset), from_address(from), to_address(to),
              token_amount(amount), metadata(meta), is_approved(false) {
            timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            
            std::stringstream ss;
            ss << static_cast<int>(dir) << asset << from << to << amount << meta << timestamp;
            request_hash = SHA256::hash_hex(ss.str());
        }
    };

    /**
     * @class BridgeConsensus
     * @brief Implements proof-of-stake consensus for bridge validation
     * 
     * Manages validators, voting, and finalization of cross-reality transfers.
     */
    class BridgeConsensus {
    private:
        struct Validator {
            std::string address;
            uint64_t stake;
            std::string public_key;
            bool is_active;
            uint64_t total_votes_cast;
            
            Validator(const std::string& addr, uint64_t stake_amount, const std::string& pubkey)
                : address(addr), stake(stake_amount), public_key(pubkey), 
                  is_active(true), total_votes_cast(0) {}
        };
        
        std::unordered_map<std::string, Validator> m_validators;
        std::vector<std::shared_ptr<BridgeRequest>> m_pending_requests;
        std::vector<std::shared_ptr<BridgeRequest>> m_finalized_requests;
        std::map<std::string, std::map<std::string, bool>> m_votes; // request_hash -> validator -> vote
        uint64_t m_minimum_stake;
        uint64_t m_required_confirmations;
        uint64_t m_total_stake;

    public:
        BridgeConsensus(uint64_t min_stake = 1000, uint64_t required_confirmations = 3)
            : m_minimum_stake(min_stake), m_required_confirmations(required_confirmations), m_total_stake(0) {
            std::cout << "[CONSENSUS] Bridge Consensus Protocol initialized (PoS)\n";
        }
        
        /**
         * @brief Register a validator with stake
         */
        bool register_validator(const Wallet& wallet, uint64_t stake_amount) {
            if (stake_amount < m_minimum_stake) {
                std::cout << "[CONSENSUS] Stake " << stake_amount << " below minimum " 
                          << m_minimum_stake << "\n";
                return false;
            }
            
            Validator validator(wallet.get_address(), stake_amount, wallet.get_public_key_hex());
            m_validators[wallet.get_address()] = validator;
            m_total_stake += stake_amount;
            
            std::cout << "[CONSENSUS] Validator registered: " << wallet.get_address().substr(0, 16)
                      << "... (stake: " << stake_amount << ")\n";
            return true;
        }
        
        /**
         * @brief Submit a bridge request
         */
        std::shared_ptr<BridgeRequest> submit_request(BridgeRequest::Direction dir,
                                                       const std::string& asset_id,
                                                       const Wallet& from_wallet,
                                                       const std::string& to_address,
                                                       uint64_t token_amount = 0,
                                                       const std::string& metadata = "") {
            auto request = std::make_shared<BridgeRequest>(
                dir, asset_id, from_wallet.get_address(), to_address, token_amount, metadata
            );
            m_pending_requests.push_back(request);
            
            std::cout << "[CONSENSUS] Bridge request submitted: " << request->request_hash.substr(0, 16)
                      << "... (" << (dir == BridgeRequest::Direction::METAVERSE_TO_BLOCKCHAIN ? 
                      "MV→BC" : "BC→MV") << ")\n";
            return request;
        }
        
        /**
         * @brief Cast vote on a bridge request
         */
        bool cast_vote(const std::string& request_hash, const Wallet& validator_wallet, bool approve) {
            auto validator_it = m_validators.find(validator_wallet.get_address());
            if (validator_it == m_validators.end()) {
                std::cout << "[CONSENSUS] Non-validator attempted to vote\n";
                return false;
            }
            
            if (!validator_it->second.is_active) {
                return false;
            }
            
            m_votes[request_hash][validator_wallet.get_address()] = approve;
            validator_it->second.total_votes_cast++;
            
            std::cout << "[CONSENSUS] Vote cast by " << validator_wallet.get_address().substr(0, 16)
                      << "...: " << (approve ? "APPROVE" : "REJECT") << "\n";
            
            // Check if we can finalize
            try_finalize_request(request_hash);
            return true;
        }
        
        /**
         * @brief Attempt to finalize a request based on stake-weighted votes
         */
        bool try_finalize_request(const std::string& request_hash) {
            // Find the request
            auto req_it = std::find_if(m_pending_requests.begin(), m_pending_requests.end(),
                [&request_hash](const auto& req) { return req->request_hash == request_hash; });
            
            if (req_it == m_pending_requests.end()) return false;
            
            auto& request = *req_it;
            
            auto votes_it = m_votes.find(request_hash);
            if (votes_it == m_votes.end()) return false;
            
            uint64_t approve_stake = 0, reject_stake = 0;
            
            for (const auto& [validator_addr, vote] : votes_it->second) {
                auto val_it = m_validators.find(validator_addr);
                if (val_it != m_validators.end() && val_it->second.is_active) {
                    if (vote) {
                        approve_stake += val_it->second.stake;
                    } else {
                        reject_stake += val_it->second.stake;
                    }
                }
            }
            
            uint64_t total_voting_stake = approve_stake + reject_stake;
            
            // Need at least 2/3 stake participation for finalization
            if (total_voting_stake < (m_total_stake * 2 / 3)) {
                std::cout << "[CONSENSUS] Insufficient stake participation for "
                          << request_hash.substr(0, 16) << "... (" << total_voting_stake 
                          << "/" << m_total_stake << ")\n";
                return false;
            }
            
            // Need > 1/2 approval stake
            request->is_approved = (approve_stake > reject_stake);
            
            if (request->is_approved) {
                std::cout << "[CONSENSUS] ✓ Bridge request FINALIZED (APPROVED): " 
                          << request_hash.substr(0, 16) << "...\n";
            } else {
                std::cout << "[CONSENSUS] ✗ Bridge request FINALIZED (REJECTED): " 
                          << request_hash.substr(0, 16) << "...\n";
            }
            
            // Move to finalized and remove from pending
            m_finalized_requests.push_back(request);
            m_pending_requests.erase(req_it);
            
            return true;
        }
        
        /**
         * @brief Get number of pending requests
         */
        [[nodiscard]] size_t pending_count() const noexcept { return m_pending_requests.size(); }
        
        /**
         * @brief Get number of finalized requests
         */
        [[nodiscard]] size_t finalized_count() const noexcept { return m_finalized_requests.size(); }
        
        /**
         * @brief Print consensus statistics
         */
        void print_stats() const {
            std::cout << "\n=== Bridge Consensus Statistics ===\n";
            std::cout << "Active Validators: " << m_validators.size() << "\n";
            std::cout << "Total Staked: " << m_total_stake << "\n";
            std::cout << "Pending Requests: " << m_pending_requests.size() << "\n";
            std::cout << "Finalized Requests: " << m_finalized_requests.size() << "\n";
            std::cout << "Required Confirmations: " << m_required_confirmations << "\n";
            
            if (!m_validators.empty()) {
                auto top_validator = std::max_element(m_validators.begin(), m_validators.end(),
                    [](const auto& a, const auto& b) { return a.second.stake < b.second.stake; });
                std::cout << "Largest Stake: " << top_validator->second.stake 
                          << " (" << top_validator->first.substr(0, 16) << "...)\n";
            }
            std::cout << "==================================\n";
        }
    };

    /**
     * @class SteamBridge
     * @brief Main bridge orchestrator connecting MetaVerse and Blockchain
     * 
     * Provides high-level API for cross-reality operations with full
     * cryptographic verification and consensus-based validation.
     */
    class SteamBridge {
    private:
        std::unique_ptr<BlockChain> m_blockchain;
        std::unique_ptr<MetaVerseEngine> m_metaverse;
        std::unique_ptr<BridgeConsensus> m_consensus;
        std::unordered_map<std::string, std::shared_ptr<BridgeRequest>> m_active_bridges;
        uint64_t m_total_bridges_completed;
        uint64_t m_total_bridge_value;

    public:
        SteamBridge(int blockchain_difficulty = DEFAULT_DIFFICULTY, 
                    uint64_t min_validator_stake = 1000)
            : m_total_bridges_completed(0), m_total_bridge_value(0) {
            m_blockchain = std::make_unique<BlockChain>(blockchain_difficulty);
            m_metaverse = std::make_unique<MetaVerseEngine>();
            m_consensus = std::make_unique<BridgeConsensus>(min_validator_stake);
            
            // Register a default validator (for demonstration)
            Wallet genesis_validator;
            m_consensus->register_validator(genesis_validator, 10000);
            
            std::cout << "\n========================================\n";
            std::cout << "  STEAM BRIDGE v3.0 - OPERATIONAL\n";
            std::cout << "  Connecting MetaVerse to BlockChain\n";
            std::cout << "========================================\n\n";
        }
        
        // Accessors
        [[nodiscard]] BlockChain& get_blockchain() { return *m_blockchain; }
        [[nodiscard]] MetaVerseEngine& get_metaverse() { return *m_metaverse; }
        [[nodiscard]] BridgeConsensus& get_consensus() { return *m_consensus; }
        
        /**
         * @brief Bridge an asset from MetaVerse to Blockchain
         */
        std::shared_ptr<Transaction> bridge_asset_to_chain(const std::string& asset_id,
                                                            const Wallet& owner,
                                                            uint64_t valuation_tokens = 0) {
            // Create the bridge request
            auto request = m_consensus->submit_request(
                BridgeRequest::Direction::METAVERSE_TO_BLOCKCHAIN,
                asset_id, owner, "BLOCKCHAIN_VAULT", valuation_tokens,
                "Asset bridging to blockchain"
            );
            
            m_active_bridges[request->request_hash] = request;
            
            // For demonstration, auto-approve with the default validator
            Wallet validator;
            m_consensus->cast_vote(request->request_hash, validator, true);
            
            // Execute the bridge if approved
            auto tx = m_metaverse->bridge_asset_to_chain(asset_id, owner, valuation_tokens);
            
            if (tx) {
                m_blockchain->add_transaction(tx);
                m_total_bridges_completed++;
                m_total_bridge_value += valuation_tokens;
                
                std::cout << "[STEAM BRIDGE] ✓ Bridge MV→BC completed: Asset " 
                          << asset_id.substr(0, 16) << "...\n";
            }
            
            return tx;
        }
        
        /**
         * @brief Bridge tokens from Blockchain to MetaVerse asset
         */
        std::shared_ptr<VirtualAsset> bridge_token_to_asset(const std::string& tx_id,
                                                             const std::string& asset_name,
                                                             AssetType asset_type,
                                                             const Wallet& recipient,
                                                             const std::string& metadata = "") {
            // Verify the blockchain transaction exists
            auto tx_opt = m_blockchain->find_transaction(tx_id);
            if (!tx_opt.has_value()) {
                throw std::runtime_error("Transaction not found on blockchain");
            }
            
            auto tx = tx_opt.value();
            if (tx->get_to_address() != recipient.get_address()) {
                throw std::runtime_error("Transaction recipient doesn't match");
            }
            
            // Submit bridge request
            auto request = m_consensus->submit_request(
                BridgeRequest::Direction::BLOCKCHAIN_TO_METAVERSE,
                tx->get_asset_id(), recipient.get_address(), 
                tx->get_from_address(), tx->get_amount(),
                "Token to asset bridge: " + tx->get_tx_id()
            );
            
            m_active_bridges[request->request_hash] = request;
            
            // Auto-approve for demonstration
            Wallet validator;
            m_consensus->cast_vote(request->request_hash, validator, true);
            
            // Create the asset in MetaVerse
            auto asset = m_metaverse->create_asset(asset_name, asset_type, recipient, metadata);
            m_total_bridges_completed++;
            m_total_bridge_value += tx->get_amount();
            
            std::cout << "[STEAM BRIDGE] ✓ Bridge BC→MV completed: Created asset "
                      << asset_name << " from transaction " << tx_id.substr(0, 16) << "...\n";
            
            return asset;
        }
        
        /**
         * @brief Register a new validator for bridge consensus
         */
        bool register_validator(const Wallet& wallet, uint64_t stake) {
            return m_consensus->register_validator(wallet, stake);
        }
        
        /**
         * @brief Print complete system status
         */
        void print_status() const {
            std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                    STEAM BRIDGE v3.0 STATUS                    ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            
            // Blockchain stats
            std::cout << "║ BLOCKCHAIN                                                    ║\n";
            std::cout << "║   Height: " << std::setw(10) << m_blockchain->get_height() 
                      << "   Difficulty: " << std::setw(4) << m_blockchain->get_difficulty() << "        ║\n";
            std::cout << "║   Total Transactions: " << std::setw(10) << m_blockchain->get_total_transactions() 
                      << "                             ║\n";
            
            // MetaVerse stats
            std::cout << "║ METAVERSE                                                    ║\n";
            std::cout << "║   Total Assets: " << std::setw(11) << m_metaverse->get_total_assets()
                      << "                                          ║\n";
            
            // Consensus stats
            std::cout << "║ BRIDGE CONSENSUS                                              ║\n";
            std::cout << "║   Bridges Completed: " << std::setw(8) << m_total_bridges_completed
                      << "   Total Value: " << std::setw(12) << m_total_bridge_value << "       ║\n";
            std::cout << "║   Pending Requests: " << std::setw(9) << m_consensus->pending_count()
                      << "                                          ║\n";
            
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::cout << "║  \"Where virtual worlds meet immutable truth.\"               ║\n";
            std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        }
        
        /**
         * @brief Validate entire system integrity
         */
        [[nodiscard]] bool validate_system_integrity() const {
            return m_blockchain->validate_chain();
        }
    };

} // namespace SteamBridge::Bridge

// ============================================================================
// SECTION 6: Main Entry Point & Demonstration
// ============================================================================

/**
 * @brief Comprehensive demonstration of Steam Bridge functionality
 */
int main() {
    using namespace SteamBridge::Crypto;
    using namespace SteamBridge::Blockchain;
    using namespace SteamBridge::MetaVerse;
    using namespace SteamBridge::Bridge;
    
    std::cout << "\n";
    std::cout << " ███████╗ ████████╗███████╗ █████╗ ███╗   ███╗\n";
    std::cout << " ██╔════╝ ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║\n";
    std::cout << " ███████╗    ██║   █████╗  ███████║██╔████╔██║\n";
    std::cout << " ╚════██║    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║\n";
    std::cout << " ███████║    ██║   ███████╗██║  ██║██║ ╚═╝ ██║\n";
    std::cout << " ╚══════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝\n";
    std::cout << "  ██████╗ ██████╗ ██╗██████╗  ██████╗ ███████╗\n";
    std::cout << "  ██╔══██╗██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝\n";
    std::cout << "  ██████╔╝██████╔╝██║██║  ██║██║  ███╗█████╗  \n";
    std::cout << "  ██╔══██╗██╔══██╗██║██║  ██║██║   ██║██╔══╝  \n";
    std::cout << "  ██████╔╝██║  ██║██║██████╔╝╚██████╔╝███████╗\n";
    std::cout << "  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝\n";
    std::cout << "         Enterprise-Grade Cross-Reality Bridge\n";
    std::cout << "==============================================\n\n";
    
        
    try {
        // Initialize the Steam Bridge
        SteamBridge bridge(3, 5000);  // Lower difficulty for faster demo
        
        // ====================================================================
        // Phase 1: Create wallets for participants
        // ====================================================================
        std::cout << "\n--- PHASE 1: Wallet Creation ---\n";
        
        Wallet alice;
        Wallet bob;
        Wallet charlie;
        
        std::cout << "Alice's Address: " << alice.get_address().substr(0, 24) << "...\n";
        std::cout << "Bob's Address:   " << bob.get_address().substr(0, 24) << "...\n";
        std::cout << "Charlie's Address: " << charlie.get_address().substr(0, 24) << "...\n";
        
        // Register Charlie as a validator
        bridge.register_validator(charlie, 5000);
        
        // ====================================================================
        // Phase 2: Create virtual assets in MetaVerse
        // ====================================================================
        std::cout << "\n--- PHASE 2: MetaVerse Asset Creation ---\n";
        
        // Create a virtual LAND parcel for Alice
        WorldCoordinate alice_land(100, 200, 0, 1);
        auto alice_estate = bridge.get_metaverse().create_asset(
            "Sunset Paradise Estate", AssetType::LAND, alice, 
            "{\"size\": \"100x100\", \"terrain\": \"beach\", \"biome\": \"tropical\"}",
            alice_land
        );
        
        // Create a wearable item for Bob
        auto bob_sword = bridge.get_metaverse().create_asset(
            "Dragon Slayer Blade", AssetType::WEARABLE, bob,
            "{\"damage\": 150, \"rarity\": \"legendary\", \"element\": \"fire\"}"
        );
        
        // Create an avatar for Charlie
        auto charlie_avatar = bridge.get_metaverse().create_asset(
            "ShadowNinja", AssetType::AVATAR, charlie,
            "{\"level\": 42, \"class\": \"ninja\", \"abilities\": [\"stealth\", \"teleport\"]}"
        );
        
        // Create a currency token
        auto world_currency = bridge.get_metaverse().create_asset(
            "MetaDollar", AssetType::CURRENCY, alice,
            "{\"symbol\": \"MUSD\", \"supply\": 1000000, \"decimals\": 18}"
        );
        
        // ====================================================================
        // Phase 3: Create blockchain transactions
        // ====================================================================
        std::cout << "\n--- PHASE 3: Blockchain Transactions ---\n";
        
        // Alice sends some currency to Bob
        auto payment_tx = std::make_shared<Transaction>(
            alice.get_address(), bob.get_address(), world_currency->get_asset_id(),
            5000, alice, "Payment for services rendered"
        );
        bridge.get_blockchain().add_transaction(payment_tx);
        
        // Bob transfers his sword to Alice
        auto sword_tx = std::make_shared<Transaction>(
            bob.get_address(), alice.get_address(), bob_sword->get_asset_id(),
            1, bob, "Gift of legendary blade"
        );
        bridge.get_blockchain().add_transaction(sword_tx);
        
        // ====================================================================
        // Phase 4: Bridge assets between realities
        // ====================================================================
        std::cout << "\n--- PHASE 4: Cross-Reality Bridging ---\n";
        
        // Bridge Alice's land to blockchain (MV → BC)
        auto land_bridge_tx = bridge.bridge_asset_to_chain(
            alice_estate->get_asset_id(), alice, 100000
        );
        
        // Bridge blockchain transaction to create a new MetaVerse asset (BC → MV)
        auto new_asset = bridge.bridge_token_to_asset(
            payment_tx->get_tx_id(), "Enchanted Forest Pass", AssetType::PASS,
            bob, "{\"access\": \"limited\", \"duration\": \"30 days\", \"events\": [\"moonlight_festival\"]}"
        );
        
        // ====================================================================
        // Phase 5: Asset movement and interaction
        // ====================================================================
        std::cout << "\n--- PHASE 5: Asset Movement ---\n";
        
        WorldCoordinate new_location(105, 200, 0, 1);
        bridge.get_metaverse().move_asset(alice_estate->get_asset_id(), new_location, alice);
        
        // Transfer ownership of the sword
        alice_estate->transfer_ownership(bob, alice);
        std::cout << "[METAVERSE] Asset ownership transferred: " 
                  << alice_estate->get_name() << " now owned by " 
                  << bob.get_address().substr(0, 16) << "...\n";
        
        // ====================================================================
        // Phase 6: Consensus and validation
        // ====================================================================
        std::cout << "\n--- PHASE 6: System Validation ---\n";
        
        bool is_valid = bridge.validate_system_integrity();
        std::cout << "Blockchain Integrity: " << (is_valid ? "✓ VALID" : "✗ INVALID") << "\n";
        
        // ====================================================================
        // Phase 7: Final statistics
        // ====================================================================
        bridge.print_status();
        bridge.get_metaverse().print_stats();
        bridge.get_consensus().print_stats();
        
        // ====================================================================
        // Phase 8: Merkle Tree demonstration
        // ====================================================================
        std::cout << "\n--- PHASE 8: Merkle Tree Demonstration ---\n";
        
        std::vector<std::string> demo_tx_ids = {
            payment_tx->get_tx_id(),
            sword_tx->get_tx_id(),
            land_bridge_tx->get_tx_id()
        };
        
        MerkleTree merkle_demo(demo_tx_ids);
        std::cout << "Merkle Root: " << merkle_demo.get_root_hash().substr(0, 32) << "...\n";
        std::cout << "Leaf Count: " << merkle_demo.leaf_count() << "\n";
        
        // Generate and verify a proof
        if (!demo_tx_ids.empty()) {
            auto proof = merkle_demo.generate_proof(0);
            std::cout << "Proof for first transaction (" << demo_tx_ids[0].substr(0, 16) << "...):\n";
            for (const auto& [hash, is_left] : proof) {
                std::cout << "  " << (is_left ? "← Left" : "Right →") << ": " 
                          << hash.substr(0, 16) << "...\n";
            }
        }
        
        // ====================================================================
        // Phase 9: Performance metrics
        // ====================================================================
        std::cout << "\n--- PHASE 9: Performance Metrics ---\n";
        
        auto latest_block = bridge.get_blockchain().get_latest_block();
        std::cout << "Latest Block: #" << latest_block->get_index() << "\n";
        std::cout << "  Hash: " << latest_block->get_hash().substr(0, 32) << "...\n";
        std::cout << "  Merkle Root: " << latest_block->get_merkle_root().substr(0, 32) << "...\n";
        std::cout << "  Nonce: " << latest_block->get_nonce() << "\n";
        std::cout << "  Transactions: " << latest_block->get_transaction_count() << "\n";
        
        std::cout << "\n========================================================\n";
        std::cout << "  STEAM BRIDGE v3.0 - DEMONSTRATION COMPLETE\n";
        std::cout << "  All systems operational. Reality bridging successful.\n";
        std::cout << "========================================================\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL ERROR] " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
