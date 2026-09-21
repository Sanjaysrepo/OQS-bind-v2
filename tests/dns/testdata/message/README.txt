The list below describes our test files.
They can also be loaded into wireshark to be inspected: Wireshark -> File -> Import From Hexdump
-----------------------------------------------------------------------------------------------------------------------------------------------
falcon512-full-message:
-----------------------------------------------------------------------------------------------------------------------------------------------
Domain Name System (response)
    Transaction ID: 0x046c
    Flags: 0x8400 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .1.. .... .... = Authoritative: Server is an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...0 .... .... = Recursion desired: Don't do query recursively
        .... .... 0... .... = Recursion available: Server can't do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 4
    Authority RRs: 0
    Additional RRs: 1
    Queries
        example: type DNSKEY, class IN
            Name: example
            [Name Length: 7]
            [Label Count: 1]
            Type: DNSKEY (48) (DNS Public Key)
            Class: IN (0x0001)
    Answers
        example: type DNSKEY, class IN
            Name: example
            Type: DNSKEY (48) (DNS Public Key)
            Class: IN (0x0001)
            Time to live: 604800 (7 days)
            Data length: 901
            Flags: 0x0100
            Protocol: 3
            Algorithm: Unknown (17)
            [Key id: 18228]
            Public Key [truncated]: 0982b959e41fe59f48b45440195c0d7eda9e657d0afd56a47c102eaa206ecdd6a7b34df216367de96d5e06ae20977924e9519209c1c42757e525a9efa1a95e94bf6ec3f42a5843922565ea981b1d661c1684d616591341c9f25ea373ab6c79924782ad661d52a7fccdce741
        example: type DNSKEY, class IN
            Name: example
            Type: DNSKEY (48) (DNS Public Key)
            Class: IN (0x0001)
            Time to live: 604800 (7 days)
            Data length: 901
            Flags: 0x0101
            Protocol: 3
            Algorithm: Unknown (17)
            [Key id: 15018]
            Public Key [truncated]: 0940f95ad97e58f00bfccf0553dbaa1e008683f52d8fba404f608167d4b8960a400b4b8d91e68fc4a069a1460d1e508e22a58f1e8ed97dddd9bcd896f122c5ec6f42f5e8cf8a4b55fdc05af2da8db0849b0be3eb4773b916c9f24d081df6ace6c64e6364bc8bbae0aadeacf
        example: type RRSIG, class IN
            Name: example
            Type: RRSIG (46) (Resource Record Signature)
            Class: IN (0x0001)
            Time to live: 604800 (7 days)
            Data length: 693
            Type Covered: DNSKEY (48) (DNS Public Key)
            Algorithm: Unknown (17)
            Labels: 1
            Original TTL: 604800 (7 days)
            Signature Expiration: Dec  9, 2025 09:51:01.000000000 AEDT
            Signature Inception: Nov  9, 2025 09:51:01.000000000 AEDT
            Key Tag: 15018
            Signer's name: example
            Signature [truncated]: 39cea1210bbb7e5021892197a0a21dab0495d4c6f174a71668e44abcb98218fb7455a8c9b84a549097759a5be590063a14a3c809b23aa14fdf658db62f3e4093ceedb32829fb5858ce07a2914fd3bd565794ac75bbc7765f81c519d4498f8fd17bb2360909cca81d7ac1124e
        example: type RRSIG, class IN
            Name: example
            Type: RRSIG (46) (Resource Record Signature)
            Class: IN (0x0001)
            Time to live: 604800 (7 days)
            Data length: 693
            Type Covered: DNSKEY (48) (DNS Public Key)
            Algorithm: Unknown (17)
            Labels: 1
            Original TTL: 604800 (7 days)
            Signature Expiration: Dec  9, 2025 09:51:01.000000000 AEDT
            Signature Inception: Nov  9, 2025 09:51:01.000000000 AEDT
            Key Tag: 18228
            Signer's name: example
            Signature [truncated]: 39a120c3f31210b4cc48ce118a68b2b8c16aa463861f2c574e496803170c9bfad3e13c248db5e1f9b90d9f49a5d3a81209745a60a979d551e0296d6ea8b327df4c5b755a32dac40888b69e1cbb328939758d5685b37e76fb7a22f1fe8173c40134a817872d829c3c3f28220d
    Additional records
        <Root>: type OPT
            Name: <Root>
            Type: OPT (41) 
            UDP payload size: 1232
            Higher bits in extended RCODE: 0x00
            EDNS0 version: 0
            Z: 0x8000
                1... .... .... .... = DO bit: Accepts DNSSEC security RRs
                .000 0000 0000 0000 = Reserved: 0x0000
            Data length: 0
    [Unsolicited: True]
-----------------------------------------------------------------------------------------------------------------------------------------------
Fragment 1:
-----------------------------------------------------------------------------------------------------------------------------------------------
Fragment 2:
Domain Name System (response)
    Transaction ID: 0x046c
    Flags: 0x8600 Standard query response, No error
    Questions: 1
    Answer RRs: 4
    Authority RRs: 0
    Additional RRs: 1
    Queries
        ?2?example: type DNSKEY, class IN
            Name: ?2?example
            [Name Length: 10]
            [Label Count: 1]
            Type: DNSKEY (48) (DNS Public Key)
            Class: IN (0x0001)
    Answers
        ?2?example: type DNSKEY, class IN
            Name: ?2?example
            Type: DNSKEY (48) (DNS Public Key)
            Class: IN (0x0001)
            Time to live: 604800 (7 days)
            Data length: 313
            Flags: 0x0100
            Protocol: 3
            Algorithm: Unknown (17)
            [Key id: 28507]
            Public Key [truncated]: 3c9a35ddc0d446bcc84628afc804eca3a4b818bb1d921eead6a442b7c9ae7b8d157c3b668594a7ed8572399707c9970b106ebcb7ab6abdaf0ebce1c8d3a67e782b4bb7c23c08868bbadb967a68eeef4796a06fbf4038d5765e6673a82cb327d5e87e28b6352520eb4e686a6
        ?2?example: type DNSKEY, class IN
        ?2?example: type RRSIG, class IN
        ?2?example: type RRSIG, class IN
    Additional records
    [Request In: 5173]
    [Time: 0.000156000 seconds]


-----------------------------------------------------------------------------------------------------------------------------------------------
Fragment 3:
Domain Name System (response)
    Transaction ID: 0x046c
    Flags: 0x8600 Standard query response, No error
    Questions: 1
    Answer RRs: 4
    Authority RRs: 0
    Additional RRs: 1
    Queries
        ?3?example: type DNSKEY, class IN
    Answers
    Additional records
    [Request In: 5175]
    [Time: 0.000124000 seconds]

-----------------------------------------------------------------------------------------------------------------------------------------------
P256_FALCON512
Description: four fragments, however, only three of them contain signatures (since the keys are larger). This is a good test-case to check.
-----------------------------------------------------------------------------------------------------------------------------------------------
