// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "checkpoints.h"
#include "primitives/block.h"
#include "protocol.h"
#include "uint256.h"

#include <vector>
#include <iostream>
#include <bitcoin/bst/claim.h>

#define PREMINE_SIZE 100000
static const int PREMINE_BLOCKS = 21;

typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

struct CDNSSeedData {
    std::string name, host;
    CDNSSeedData(const std::string &strName, const std::string &strHost) : name(strName), host(strHost) {}
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const uint256& HashGenesisBlock() const { return hashGenesisBlock; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    const std::vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; }
    const uint256& ProofOfWorkLimit() const { return bnProofOfWorkLimit; }
    int SubsidyHalvingInterval() const { return nSubsidyHalvingInterval; }
    /** Used to check majorities for block version upgrade */
    int EnforceBlockUpgradeMajority() const { return nEnforceBlockUpgradeMajority; }
    int RejectBlockOutdatedMajority() const { return nRejectBlockOutdatedMajority; }
    int ToCheckBlockUpgradeMajority() const { return nToCheckBlockUpgradeMajority; }

    /** Used if GenerateBitcoins is called with a negative number of threads */
    int DefaultMinerThreads() const { return nMinerThreads; }
    const CBlock& GenesisBlock() const { return genesis; }
    bool RequireRPCPassword() const { return fRequireRPCPassword; }
    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Allow mining of a min-difficulty block */
    bool AllowMinDifficultyBlocks() const { return fAllowMinDifficultyBlocks; }
    /** Skip proof-of-work check: allow mining of any difficulty block */
    bool SkipProofOfWorkCheck() const { return fSkipProofOfWorkCheck; }
    /** Make standard checks */
    bool RequireStandard() const { return fRequireStandard; }
    int64_t TargetTimespan() const { return nTargetTimespan; }
    int64_t TargetSpacing() const { return nTargetSpacing; }
    int64_t Interval() const { return nTargetTimespan / nTargetSpacing; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** In the future use NetworkIDString() for RPC fields */
    bool TestnetToBeDeprecatedFieldRPC() const { return fTestnetToBeDeprecatedFieldRPC; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    const std::vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::vector<CAddress>& FixedSeeds() const { return vFixedSeeds; }
    virtual const Checkpoints::CCheckpointData& Checkpoints() const = 0;
    virtual bool IsPremineHash(const uint256 hash) = 0;
    virtual const uint32_t* getNonceList() const = 0;

    // Litecoin: Height to enforce v2 block
    int EnforceV2AfterHeight() const { return nEnforceV2AfterHeight; }
protected:
    CChainParams() {}

    uint256 hashGenesisBlock;
    MessageStartChars pchMessageStart;
    //! Raw pub key bytes for the broadcast alert signing key.
    std::vector<unsigned char> vAlertPubKey;
    int nDefaultPort;
    uint256 bnProofOfWorkLimit;
    int nSubsidyHalvingInterval;
    int nEnforceBlockUpgradeMajority;
    int nRejectBlockOutdatedMajority;
    int nToCheckBlockUpgradeMajority;
    int64_t nTargetTimespan;
    int64_t nTargetSpacing;
    int nMinerThreads;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    CBaseChainParams::Network networkID;
    std::string strNetworkID;
    CBlock genesis;
    std::vector<CAddress> vFixedSeeds;
    bool fRequireRPCPassword;
    bool fMiningRequiresPeers;
    bool fAllowMinDifficultyBlocks;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    bool fSkipProofOfWorkCheck;
    bool fTestnetToBeDeprecatedFieldRPC;

    // Litecoin: Height to enforce v2 blocks
    int nEnforceV2AfterHeight;
};

class PremineBlocks {
    bst::snapshot_reader snapshot_reader;
    std::ifstream stream;
    const CBlock& genesis;
    const uint32_t* nonceList;

public:
    PremineBlocks(const CBlock& genesis_, const uint32_t* nonceList_) : genesis(genesis_), nonceList(nonceList_) {
        assert(bst::openSnapshot(stream, snapshot_reader));
    }
    PremineBlocks(const PremineBlocks& other) : genesis(other.genesis), nonceList(other.nonceList) {
        assert(bst::openSnapshot(stream, snapshot_reader));
    }

    class const_iterator {
    public:
        typedef const_iterator self_type;
        typedef CBlock value_type;
        typedef const CBlock& reference;
        typedef const CBlock* pointer;
        typedef int64_t difference_type;
        typedef std::input_iterator_tag iterator_category;

        const_iterator(bst::snapshot_reader reader_, const CBlock& genesis, const uint32_t* nonceList_) : nonceList(nonceList_), index(0) {
            reader = reader_;
            current_block.nVersion = genesis.nVersion;
            current_block.nTime = genesis.nTime + 1;
            current_block.nBits = genesis.nBits;
            current_block.hashPrevBlock = genesis.GetHash();
        }
        const_iterator(bst::snapshot_reader reader_, int64_t index_) {
            index = index_;
        }

        // this operator is post-increment, so we have to return the current value and then change it
        self_type operator++() {
            self_type i = *this; index++; return i;
        }
        self_type operator++(int junk) {
            index++;
            current_block.hashPrevBlock = current_block.GetHash();
            current_block.nTime++;
            return *this;
        }
        reference operator*() {
            uint64_t start = index * PREMINE_SIZE;
            uint64_t end = (index + 1) * PREMINE_SIZE;
            end = end > reader.header.nP2PKH + reader.header.nP2SH ? reader.header.nP2PKH + reader.header.nP2SH : end;

            bst::SnapshotEntryCollection p2pkh_collection = bst::getP2PKHCollection(reader);
            bst::SnapshotEntryCollection p2sh_collection = bst::getP2SHCollection(reader);

            current_block.vtx.clear();
            CMutableTransaction txNew;
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            CScript fakeSign = CScript() << 486604799;
            txNew.vin[0].scriptSig = fakeSign;
            for (uint64_t i = start; i < end; i++) {
                bst::snapshot_entry entry;

                if (i >= reader.header.nP2PKH) {
                    p2sh_collection.getEntry(i - reader.header.nP2PKH, entry);
                    txNew.vout[0].nValue = entry.amount;
                    txNew.vout[0].scriptPubKey = CScript() << OP_HASH160 << entry.hash << OP_EQUAL;
                } else {
                    p2pkh_collection.getEntry(i, entry);
                    txNew.vout[0].nValue = entry.amount;
                    txNew.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << entry.hash << OP_EQUALVERIFY << OP_CHECKSIG;
                }
                current_block.vtx.push_back(txNew);
            }
            current_block.hashMerkleRoot = current_block.BuildMerkleTree();

            // fix nonce so that PoW requirement is met
            /*
            bool fNegative;
            bool fOverflow;
            uint256 bnTarget;
            bnTarget.SetCompact(current_block.nBits, &fNegative, &fOverflow);
            for (unsigned int i = 0; true; i++) {
                current_block.nNonce = i;
                uint256 powHash = current_block.GetPoWHash();
                if (powHash <= bnTarget) break;
            }
             */
            current_block.nNonce = nonceList[index];

            std::cout << "premine block " << current_block.GetHash().ToString()
              << " nonce " << current_block.nNonce << endl;

            return current_block;
        }
        pointer operator->() { return &(**this); }
        bool operator==(const self_type& rhs) { return index == rhs.index; }
        bool operator!=(const self_type& rhs) { return index != rhs.index; }
    private:
        const uint32_t* nonceList;
        uint64_t index;
        bool done_p2pkh;
        int64_t block_index;
        CBlock current_block;
        bst::snapshot_reader reader;
    };

    const_iterator begin() const { return const_iterator(snapshot_reader, genesis, nonceList);}
    const_iterator end() const {
        int premineBlocks = ((int) snapshot_reader.header.nP2PKH + snapshot_reader.header.nP2SH + 1) / PREMINE_SIZE;
        return const_iterator(snapshot_reader, premineBlocks);
        }
};

/** 
 * Modifiable parameters interface is used by test cases to adapt the parameters in order
 * to test specific features more easily. Test cases should always restore the previous
 * values after finalization.
 */

class CModifiableParams {
public:
    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) =0;
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)=0;
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)=0;
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)=0;
    virtual void setDefaultConsistencyChecks(bool aDefaultConsistencyChecks)=0;
    virtual void setAllowMinDifficultyBlocks(bool aAllowMinDifficultyBlocks)=0;
    virtual void setSkipProofOfWorkCheck(bool aSkipProofOfWorkCheck)=0;
};


/**
 * Return the currently selected parameters. This won't change after app startup
 * outside of the unit tests.
 */
const CChainParams &Params();

/** Return parameters for the given network. */
CChainParams &Params(CBaseChainParams::Network network);

/** Get modifiable network parameters (UNITTEST only) */
CModifiableParams *ModifiableParams();

/** Sets the params returned by Params() to those for the given network. */
void SelectParams(CBaseChainParams::Network network);

/**
 * Looks for -regtest or -testnet and then calls SelectParams as appropriate.
 * Returns false if an invalid combination is given.
 */
bool SelectParamsFromCommandLine();

bool IsPreminedBlock(const CBlock& block);


#endif // BITCOIN_CHAINPARAMS_H
