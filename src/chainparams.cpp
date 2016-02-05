// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

static const uint256 PREMINE_HASH1  = uint256("9ed215827aebb56bdab34c70427403c3b3b9321c131f8540747e3b4efc66ae40");
static const uint256 PREMINE_HASH2  = uint256("11a0f7f84b6766eaa67a64b4ae9c60d19c03df05fe9c703c38c9e441d0a4c937");
static const uint256 PREMINE_HASH3  = uint256("b00b72f5c2b9514fe63f6f305180e7e7baca316df21855b5b373fd6cab9126ee");
static const uint256 PREMINE_HASH4  = uint256("8cb60e65a7b926ab4fb0599d461f31a9986d97a45e4e722d1d9e7a6ab03375b2");
static const uint256 PREMINE_HASH5  = uint256("dbbfba1cad159f85cc4e96f88f7954f07d0a58744f2de9aadb574e72c5c6f587");
static const uint256 PREMINE_HASH6  = uint256("8991218b14892407676e12c3127d76ee0aa2d5a00c171a791dbc73084dc96f85");
static const uint256 PREMINE_HASH7  = uint256("1ac7b23ad3c2ef6d67087d8ec6518d23b6b52d0cb37a124504045a450630a5cd");
static const uint256 PREMINE_HASH8  = uint256("53950086bcfb748e297f46ed9236575496f382dd30d25129c5b4ec5679298c4a");
static const uint256 PREMINE_HASH9  = uint256("9d9815d91cae621ae005b2e5515b71824313ce8e56deea7215672fad27ed4924");
static const uint256 PREMINE_HASH10 = uint256("8fb3ba9634212878d406784df2f90f81c7e04fb85c25f6704aefaa48fcd2fa88");
static const uint256 PREMINE_HASH11 = uint256("d9ac66a33cb5a27df64ecb66515013c23f32aeea6a9eefcc828c30e5fa4e036f");
static const uint256 PREMINE_HASH12 = uint256("28d548adb8ebf17063a8025a3a301f0e7c25701484469bbcf6ccc04f101074e2");
static const uint256 PREMINE_HASH13 = uint256("ed9aab9fe7bc8598eedd41d37f26079a3e842560d7a07df1dc63a0d862248a74");
static const uint256 PREMINE_HASH14 = uint256("de9dc637328f704f4b775431afcae31db3d3ae6ba6a9e2ad46eb1ef36043759c");
static const uint256 PREMINE_HASH15 = uint256("589a53f5c26556bcb0075d1015eaa47ec4161e1c79adb55627645f0ee8207b2a");
static const uint256 PREMINE_HASH16 = uint256("abe261d925ea4dbd86a1c338ea9325e27ec386fd2264615270402e6fb330799a");
static const uint256 PREMINE_HASH17 = uint256("e5aaceb92712f85ccef33f2a57d7db360d99dd97c656b89faef4f4df2e2fabc9");
static const uint256 PREMINE_HASH18 = uint256("ddf972f9fdfbca10f700fa23fc1954bd3c1db1d60a226b19a0154d511e0383d2");
static const uint256 PREMINE_HASH19 = uint256("9e1cd1da45d5fe4476d6868e6dc8b063bbd49e8610363b7d7ac1f0dbea23124e");
static const uint256 PREMINE_HASH20 = uint256("21eb3151c1750680bdc20e020b2cf08ca6d86c2c8b7d408920d610df45d6a7a7");
static const uint256 PREMINE_HASH21 = uint256("a5ea1227c0012bc9a760b9ac3d3fc96ddaafc2971c5f1bb0f85fde39cf508bbb");
static const uint256* PREMINE_HASHES[PREMINE_BLOCKS] = {
        &PREMINE_HASH1,
        &PREMINE_HASH2,
        &PREMINE_HASH3,
        &PREMINE_HASH4,
        &PREMINE_HASH5,
        &PREMINE_HASH6,
        &PREMINE_HASH7,
        &PREMINE_HASH8,
        &PREMINE_HASH9,
        &PREMINE_HASH10,
        &PREMINE_HASH11,
        &PREMINE_HASH12,
        &PREMINE_HASH13,
        &PREMINE_HASH14,
        &PREMINE_HASH15,
        &PREMINE_HASH16,
        &PREMINE_HASH17,
        &PREMINE_HASH18,
        &PREMINE_HASH19,
        &PREMINE_HASH20,
        &PREMINE_HASH21
};
static const uint256 TESTNET_PREMINE_HASH1  = uint256("a8be47f7fb336006ad892025060f43f42b62b110fce50163e545accfb8c61676");
static const uint256 TESTNET_PREMINE_HASH2  = uint256("a222bb774ef184e41424c1d417fab2e39926941840bf5198b7f00be180b92f02");
static const uint256 TESTNET_PREMINE_HASH3  = uint256("90c1d06d5d8c0fc7aa3b297357c9c8896f9046493cc4259977e9d93f4ea38685");
static const uint256 TESTNET_PREMINE_HASH4  = uint256("6760f3337efadf0c1f79218bfa92f07d26dbef0be14580fefe16181f9561bcb9");
static const uint256 TESTNET_PREMINE_HASH5  = uint256("bc96c744d32067d88bfef799d978230988582a2f0d3315d5b444d65b552c28e2");
static const uint256 TESTNET_PREMINE_HASH6  = uint256("f7f127bbe120cac22a0960733ac6b7c1776cfba60a12c3974c20594c61dcc454");
static const uint256 TESTNET_PREMINE_HASH7  = uint256("426c7755c2c9d67d437e2d085ecbf9255a35d129ca763fea15715ebc98b8d004");
static const uint256 TESTNET_PREMINE_HASH8  = uint256("5e3b4df5a19bea10186e538bf76b7bd87d3829739c4b07748dd9abdce4a5d6fb");
static const uint256 TESTNET_PREMINE_HASH9  = uint256("c98815ae48df129203bee199e90032554a9c787980c7c0daafc5d48a20f2585b");
static const uint256 TESTNET_PREMINE_HASH10 = uint256("a927da94dbc172fa43aa4494cb596ca495b8ba69cd18fc9ed9ea2ed8b58bbc0a");
static const uint256 TESTNET_PREMINE_HASH11 = uint256("e874cb69019f293413c496df38f660bc6e15c822bc721ed26cfdbdec2e2e7438");
static const uint256 TESTNET_PREMINE_HASH12 = uint256("608795846f29a660671e874fc12f6d7ba103dd22e6b52fac3e093cf0013d8b89");
static const uint256 TESTNET_PREMINE_HASH13 = uint256("3bfc72e385ff7bdf19e36d93f609b4c02cf0be7dfc04d36aef0ae21d00f27a92");
static const uint256 TESTNET_PREMINE_HASH14 = uint256("e75342454c9c117f0be7e1ce49123eadbccba464bda93fb34368e1891c231441");
static const uint256 TESTNET_PREMINE_HASH15 = uint256("a3af504b4ae28164d5eabe7faee985470cd962d19a1c3b45cc2b1ecb68215f97");
static const uint256 TESTNET_PREMINE_HASH16 = uint256("6722bbf30e92ea0cc2e412ab259bb00c046e640195c2401e6843d065fc653943");
static const uint256 TESTNET_PREMINE_HASH17 = uint256("9e4acea535d00e0376e4656b794ec835be8c9a6cede6f9e516e944a8357d4b37");
static const uint256 TESTNET_PREMINE_HASH18 = uint256("7be78a3fa95a22bf5c66298c654fa937eddd216bbbdb9e092c28d4fe4ecd02e1");
static const uint256 TESTNET_PREMINE_HASH19 = uint256("319be1f89ed6305cf3e15e2b210d3fcefad724eb0ebdb9a0800f777019aee3d9");
static const uint256 TESTNET_PREMINE_HASH20 = uint256("3bdbbd815d6ecb62b5ebf4f5310a1edb49982d4aa571f85ffe48dd2a01988170");
static const uint256 TESTNET_PREMINE_HASH21 = uint256("5a7d67d69d9e43fba82dc522cb7e6aed2a5891749826c8755cd26cc510766a79");
static const uint256* TESTNET_PREMINE_HASHES[PREMINE_BLOCKS] = {
        &TESTNET_PREMINE_HASH1,
        &TESTNET_PREMINE_HASH2,
        &TESTNET_PREMINE_HASH3,
        &TESTNET_PREMINE_HASH4,
        &TESTNET_PREMINE_HASH5,
        &TESTNET_PREMINE_HASH6,
        &TESTNET_PREMINE_HASH7,
        &TESTNET_PREMINE_HASH8,
        &TESTNET_PREMINE_HASH9,
        &TESTNET_PREMINE_HASH10,
        &TESTNET_PREMINE_HASH11,
        &TESTNET_PREMINE_HASH12,
        &TESTNET_PREMINE_HASH13,
        &TESTNET_PREMINE_HASH14,
        &TESTNET_PREMINE_HASH15,
        &TESTNET_PREMINE_HASH16,
        &TESTNET_PREMINE_HASH17,
        &TESTNET_PREMINE_HASH18,
        &TESTNET_PREMINE_HASH19,
        &TESTNET_PREMINE_HASH20,
        &TESTNET_PREMINE_HASH21
};
static const uint32_t TESTNET_PREMINE_NONCES[PREMINE_BLOCKS] = {
        2452575,
        2988235,
        678135,
        407033,
        392792,
        3288496,
        889545,
        495695,
        1115810,
        1383488,
        775433,
        3518995,
        396383,
        19244,
        2795577,
        157013,
        435587,
        424066,
        2024806,
        992423,
        1755532
};
static const uint256 REGTEST_PREMINE_HASH1  = uint256("9ed215827aebb56bdab34c70427403c3b3b9321c131f8540747e3b4efc66ae40");
static const uint256 REGTEST_PREMINE_HASH2  = uint256("11a0f7f84b6766eaa67a64b4ae9c60d19c03df05fe9c703c38c9e441d0a4c937");
static const uint256 REGTEST_PREMINE_HASH3  = uint256("b00b72f5c2b9514fe63f6f305180e7e7baca316df21855b5b373fd6cab9126ee");
static const uint256 REGTEST_PREMINE_HASH4  = uint256("8cb60e65a7b926ab4fb0599d461f31a9986d97a45e4e722d1d9e7a6ab03375b2");
static const uint256 REGTEST_PREMINE_HASH5  = uint256("dbbfba1cad159f85cc4e96f88f7954f07d0a58744f2de9aadb574e72c5c6f587");
static const uint256 REGTEST_PREMINE_HASH6  = uint256("8991218b14892407676e12c3127d76ee0aa2d5a00c171a791dbc73084dc96f85");
static const uint256 REGTEST_PREMINE_HASH7  = uint256("1ac7b23ad3c2ef6d67087d8ec6518d23b6b52d0cb37a124504045a450630a5cd");
static const uint256 REGTEST_PREMINE_HASH8  = uint256("53950086bcfb748e297f46ed9236575496f382dd30d25129c5b4ec5679298c4a");
static const uint256 REGTEST_PREMINE_HASH9  = uint256("9d9815d91cae621ae005b2e5515b71824313ce8e56deea7215672fad27ed4924");
static const uint256 REGTEST_PREMINE_HASH10 = uint256("8fb3ba9634212878d406784df2f90f81c7e04fb85c25f6704aefaa48fcd2fa88");
static const uint256 REGTEST_PREMINE_HASH11 = uint256("d9ac66a33cb5a27df64ecb66515013c23f32aeea6a9eefcc828c30e5fa4e036f");
static const uint256 REGTEST_PREMINE_HASH12 = uint256("28d548adb8ebf17063a8025a3a301f0e7c25701484469bbcf6ccc04f101074e2");
static const uint256 REGTEST_PREMINE_HASH13 = uint256("ed9aab9fe7bc8598eedd41d37f26079a3e842560d7a07df1dc63a0d862248a74");
static const uint256 REGTEST_PREMINE_HASH14 = uint256("de9dc637328f704f4b775431afcae31db3d3ae6ba6a9e2ad46eb1ef36043759c");
static const uint256 REGTEST_PREMINE_HASH15 = uint256("589a53f5c26556bcb0075d1015eaa47ec4161e1c79adb55627645f0ee8207b2a");
static const uint256 REGTEST_PREMINE_HASH16 = uint256("abe261d925ea4dbd86a1c338ea9325e27ec386fd2264615270402e6fb330799a");
static const uint256 REGTEST_PREMINE_HASH17 = uint256("e5aaceb92712f85ccef33f2a57d7db360d99dd97c656b89faef4f4df2e2fabc9");
static const uint256 REGTEST_PREMINE_HASH18 = uint256("ddf972f9fdfbca10f700fa23fc1954bd3c1db1d60a226b19a0154d511e0383d2");
static const uint256 REGTEST_PREMINE_HASH19 = uint256("9e1cd1da45d5fe4476d6868e6dc8b063bbd49e8610363b7d7ac1f0dbea23124e");
static const uint256 REGTEST_PREMINE_HASH20 = uint256("21eb3151c1750680bdc20e020b2cf08ca6d86c2c8b7d408920d610df45d6a7a7");
static const uint256 REGTEST_PREMINE_HASH21 = uint256("a5ea1227c0012bc9a760b9ac3d3fc96ddaafc2971c5f1bb0f85fde39cf508bbb");
static const uint256* REGTEST_PREMINE_HASHES[PREMINE_BLOCKS] = {
        &REGTEST_PREMINE_HASH1,
        &REGTEST_PREMINE_HASH2,
        &REGTEST_PREMINE_HASH3,
        &REGTEST_PREMINE_HASH4,
        &REGTEST_PREMINE_HASH5,
        &REGTEST_PREMINE_HASH6,
        &REGTEST_PREMINE_HASH7,
        &REGTEST_PREMINE_HASH8,
        &REGTEST_PREMINE_HASH9,
        &REGTEST_PREMINE_HASH10,
        &REGTEST_PREMINE_HASH11,
        &REGTEST_PREMINE_HASH12,
        &REGTEST_PREMINE_HASH13,
        &REGTEST_PREMINE_HASH14,
        &REGTEST_PREMINE_HASH15,
        &REGTEST_PREMINE_HASH16,
        &REGTEST_PREMINE_HASH17,
        &REGTEST_PREMINE_HASH18,
        &REGTEST_PREMINE_HASH19,
        &REGTEST_PREMINE_HASH20,
        &REGTEST_PREMINE_HASH21
};
static const uint32_t REGTEST_PREMINE_NONCES[PREMINE_BLOCKS] = {
        1,
        0,
        1,
        1,
        0,
        1,
        0,
        1,
        3,
        0,
        3,
        0,
        2,
        0,
        2,
        0,
        3,
        1,
        0,
        0,
        0
};

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (PREMINE_BLOCKS, *PREMINE_HASHES[PREMINE_BLOCKS - 1])
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1422681363, // * UNIX timestamp of last checkpoint block
        5502192,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        5500.0     // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        (PREMINE_BLOCKS, *TESTNET_PREMINE_HASHES[PREMINE_BLOCKS - 1])
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1365458829,
        547,
        576
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        (PREMINE_BLOCKS, *REGTEST_PREMINE_HASHES[PREMINE_BLOCKS - 1])
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        1365458829,
        547,
        0
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        vAlertPubKey = ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9");
        nDefaultPort = 9333;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        nSubsidyHalvingInterval = 840000;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 2.5 * 60; // 2.5 minutes

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
         *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
         *   vMerkleTree: 4a5e1e
         */
        const char* pszTimestamp = "NY Times 05/Oct/2011 Steve Jobs, Apple’s Visionary, Dies at 56";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1317972665;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 2084524493;

        //TODO uncomment and fix
        /*
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"));
        assert(genesis.hashMerkleRoot == uint256("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));
         */

        // TODO: fix
        vSeeds.push_back(CDNSSeedData("bitcoin-lite.com", "dnsseed.bitcoin-lite.com"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(52);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(9);
        base58Prefixes[SECRET_KEY] =     list_of(176);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Litecoin: Mainnet v2 enforced after premine
        nEnforceV2AfterHeight = PREMINE_BLOCKS;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return data;
    }
    bool IsPremineHash(const uint256 hash) {
        for (int i = 0; i < PREMINE_BLOCKS; i++) {
            if (! hash.CompareTo(*PREMINE_HASHES[i])) return true;
        }
        return false;
    }
    const uint32_t* getNonceList() const { return TESTNET_PREMINE_NONCES; }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        vAlertPubKey = ParseHex("0449623fc74489a947c4b15d579115591add020e53b3490bf47297dfa3762250625f8ecc2fb4fc59f69bdce8f7080f3167808276ed2c79d297054367566038aa82");
        nDefaultPort = 19333;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 2.5 * 60; // 2.5 minutes

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1317798646;
        genesis.nNonce = 385270584;
        hashGenesisBlock = genesis.GetHash();
        //assert(hashGenesisBlock == uint256("0xf5ae71e26c74beacc88382716aced69cddf3dffff24f384e1808905e0188f68f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // TODO: fix
        vSeeds.push_back(CDNSSeedData("bitcoin-lite.com", "testnet-seed.bitcoin-lite.com"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        // Litecoin: Testnet v2 enforced after premine
        nEnforceV2AfterHeight = PREMINE_BLOCKS + 1;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
    bool IsPremineHash(const uint256 hash) {
        for (int i = 0; i < PREMINE_BLOCKS; i++) {
            if (! hash.CompareTo(*TESTNET_PREMINE_HASHES[i])) return true;
        }
        return false;
    }
    const uint32_t* getNonceList() const { return TESTNET_PREMINE_NONCES; }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1296688602;
        genesis.nBits = 0x207fffff;
        bool fNegative;
        bool fOverflow;
        uint256 bnTarget;
        bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
        for (unsigned int i = 0; true; i++) {
            genesis.nNonce = i;
            uint256 powHash = genesis.GetPoWHash();
            if (powHash <= bnTarget) break;
        }
        cout << "nonce is " << genesis.nNonce << endl;
        //genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 19444;
        cout << "hashGenesisBlock " << hashGenesisBlock.ToString() << endl;
        assert(hashGenesisBlock == uint256("530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Litecoin: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
    bool IsPremineHash(const uint256 hash) {
        for (int i = 0; i < PREMINE_BLOCKS; i++) {
            if (! hash.CompareTo(*REGTEST_PREMINE_HASHES[i])) return true;
        }
        return false;
    }
    const uint32_t* getNonceList() const { return REGTEST_PREMINE_NONCES; }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        // Litecoin: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

bool IsPreminedBlock(const CBlock& block)
{
    uint256 blockHash = block.GetHash();
    return pCurrentParams->IsPremineHash(blockHash);
}
