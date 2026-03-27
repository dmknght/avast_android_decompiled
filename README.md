# Database Decompiler for Avast Android (yes it's AI slop)

## What's this?

This is a Python project that decompiles Avast Mobile databases, translates the logic to pseudo Yara rule, and simulates the scan engine of Android version. The whole logic is based on decompiled Java code from Avast Android, and using Cursor to create the result (because I suck...). This project focuses on string matching engine and the database data.

## Why this project?

While Reverse Engineering Antivirus Engines is really rare, some researchers have done it:
- [Reverse engineering Kaspersky Internet Security on MacOS](https://objective-see.org/blog/blog_0x22.html)
- [Reverse engineering Windows Defender's database](https://github.com/commial/experiments/tree/master/windows-defender/VDM)
- Other research like "Windows Offender" (focused on Windows Defender's emulator), Comodo IS sandbox, ....

AFAIK, there's no article about Avast's engine (especially their string matching engine). After reading decompiled bytecode from bytecode-viewer, I got lucky:

- Most of code is written in Java rather than saved in ELF file. It's easier to export code and then analyze with Cursor.
- I managed to identify the important functions (methods).
- The codebase is likely a smaller version from Desktop counterpart. Therefore, it's much faster to get the job done.

I hope this project is helpful:

- For red teamers: Evasion.
- For others: Better understanding how Avast (or AV in general) detects a file as malicious.

For the record, this is not the first time [I analyzed](https://www.cve.org/CVERecord?id=CVE-2025-4134) Avast engine. So while this is the AI generated project, it's not like a completely AI stuff made by a hacker-wannabe skiddie.

## Avast database structure

### A quick view
Avast databases are split into multiple files. Virus definitions are stored in 2 files. For example, the Desktop version has: `db_cmd.nmp` and `db_cmd.sig` or `db_elf.nmp` and `db_elf.sig`.

From quick analysis, `.nmp` files contain obfuscated strings.

```
00000430: 0101 0301 0101 0101 0101 0101 e11d 5767  ..............Wg
00000440: 6061 7038 4401 fd58 0106 d11d 6073 7370  `ap8D..X....`ssp
00000450: 6738 54f9 7746 7063 707b 3854 f07b 736c  g8T.wFpcp{8T.{sl
00000460: 7938 54e8 6167 7074 7871 7a7a 6738 5403  y8T.agptxqzzg8T.
00000470: f470 7479 7067 3850 0101 0202 01e7 7a62  .ptypg8P......zb
00000480: 7462 746c 3850 f867 7838 54f3 7865 3854  tbtl8P.gx8T.xe8T
00000490: d47e 5679 667d 3854 b362 7a67 7127 2526  .~Vyf}8T.bzgq'%&
000004a0: 2638 54a8 637c 6761 6038 41fe 5206 079c  &8T.c|ga`8A.R...
000004b0: 6460 7c71 717a 6638 5492 656c 506c 7056  d`|qqzf8T.elPlpV
000004c0: 7a79 7970 7661 7a67 3850 0101 0101 03ec  zyypvazg8P......
000004d0: 5472 707b 6138 5001 0101 0306 0102 dd66  Trp{a8P........f
000004e0: 667d 3854 d779 7a76 7e38 54cf 7076 6167  f}8T.yzv~8T.pvag
000004f0: 7038 56fb 7067 3850 01c1 7462 7b46 797a  p8V.pg8P..tb{Fyz
00000500: 617d 3854 f667 7e38 54b1 7a67 7e38 56fb  a}8T.g~8T.zg~8V.
00000510: 7a73 7067 3840 0103 0101 010d 04f3 7e6c  zspg8@........~l
00000520: 7a61 3854 f71b 667d 6338 54fc 6676 747b  za8T..f}c8T.fvt{
00000530: 3847 0501 0740 0101 0101 0201 0501 0301  8G...@..........
00000540: 0101 0102 0101 0101 0201 0101 e459 d977  .............Y.w
```

Strings in data suggest it's using some kind of letter rotation or XOR encryption. After analyzing and brute forcing, I found out it uses XOR encryption with the key value `0x15`. So the result of a string is like `agptxqzzg8T ^ \x15 = treamdoor-A`. Sounds like name of Malware, right? Apparently, `nmp` stands for `namepool`.

The other file extension `.sig` contains binary data only. The structure of Android counterpart is similar, but smaller. My guess is, the Database is designed to detect DEX bytecode, and ELF files on ARM only which is reasonable:

```
db_dex.map
db_dex.nmp
db_elfa.map
db_elfa.nmp
```

With the help of Cursor and the decompiled code, `.nmp` file contains virus signature names with token id / reference values. But the detection logic is more important. It should be in the `.map` file.

### RE result (1): .map file structure

```
 +---------------------------+ 12 bytes
 | MAGIC                     |  "AvastVpsST1+" (SINGLE_STRING)
 |                           |  or "AvastVpsMS2+" (MULTI_STRING)
 +---------------------------+
 | u32 payload_len           |  LE; = file_size - 16 (integrity)
 +---------------------------+ 4 bytes (There's no chunk / gap in between)
 | u32 blob0_len             |
 +---------------------------+
 | BLOB payload[blob0_len]   |
 +---------------------------+
 | u32 blob1_len             |
 +---------------------------+
 | BLOB payload[blob1_len]   |
 +---------------------------+
 |    ...........            |  BLOBS are mapped with COUNTER
 +---------------------------+
 | u32 blob6_len             |
 +---------------------------+
 | BLOB payload[blob6_len]   |
 +---------------------------+
```

Each **BLOB** on disk is either 1 of 7 **COUNTER**, following order below: STRINGS_BLOB, STRING_GROUPS_BLOB, RULE_GROUPS_BLOB, VIRUS_REPORTS_BLOB, HEUR_SUBMITS_BLOB, RULE_GROUPS_ID_MAPPER_BLOB, NAME_POOL_INDEX_BLOB.

- **RULE_GROUPS_BLOB**, **VIRUS_REPORTS_BLOB**, **HEUR_SUBMITS_BLOB**, **RULE_GROUPS_ID_MAPPER_BLOB**, **NAME_POOL_INDEX_BLOB**: Likely it's not in the Android version, which has database format as `.map` instead of `.sig`.

- There are 2 other counters **CERT_ALLOWED_PARTNERS** and **CERT_WHITELIST** has slot order `0` (same slot as `STRINGS_BLOB`) and `1` (same slot as  `STRING_GROUPS_BLOB`)


### RE result (2): STRINGS_BLOB structure

- **STRINGS_BLOB**: Module name in decompiled code is called `kb10`. It has bloom filter and group filter before using pattern's value for string matching. String matching compares input bytes against pattern_byte XOR 0xA5: `[match_result] = ([input_data] == [pattern] ^ 0xA5)`. But in wildcard mode, bytes equal to wildcard_const XOR 0xA5 are treated as skip bytes `[skip] = ([input_data] == [wildcard_const] ^ 0xA5)`

```
 +----------------------------+ 40 bytes (9×u32 + skip 4)
 | kb10 header               |
 |  u32 a0                   |
 |  u32 scan_limit           |  How much of the input is eligible for scanning in this model
 |  u32 bloom_len            |  Size of the bloom bitset
 |  u32 group_len            |  Size of the group record array. group_len / 16 records
 |  u32 pattern_len          |  Total bytes for all leaf patterns records
 |  u32 var7                 |
 |  u32 skip2, skip4, skip3  |
 |  u32 (skip 4 byte)        |
 +---------------------------+
 | BLOOM[bloom_len]          |  Bloom bitset for fast filtering (after rolling hash)
 +---------------------------+
 | GROUP[group_len]          |  Routing filter table. Refers to candidate
 |   [GR0][GR1]...[GRn-1]    |  pattern ranges / routing metadata.
 |   n = group_len / 16      |
 +---------------------------+
 | PATTERN[pattern_len]      |  It's a so called a leaf. More detailed
 |   [META_DATA][CMP_BYTE]   |  structure is below (in Pattern Record)
 +---------------------------+
 | pad/skip                  |  skip2 + skip4 + skip3
 +---------------------------+
 ```

- Group record: a routing/filter table. Each record refers to a bucket (defined by hash and group mask). After passing bloom filter, `kb10` uses the input to pick a group of patterns

 ```
 +--------------------------------------+ 16 bytes / record (fixed)
 | GROUP RECORD (GRi)                   |
 |  byte prefix_0                       |  hash/group prefilter byte
 |  byte prefix_1                       |  hash/group prefilter byte
 |  byte prefix_2                       |  hash/group prefilter byte
 |  s8   d                              |  signed control byte
 |  u32  c   (LE)                       |  route/filter value
 |  u32  e   (LE)                       |  route/filter value
 |  u32  a   (LE)                       |  route/filter value
 +--------------------------------------+
  ```

- Pattern record: Each pattern record represents one leaf detection condition:

 ```
 +--------------------------------------+ variable size (8 + L bytes)
 | PATTERN RECORD (leaf)                |
 |  u32  pattern_record_id (LE)         |  leaf id
 |  u8   reversed/unknown               |  unknown
 |  u8   wc                             |  wildcard constant (0 => exact)
 |  u8   L                              |  compare_len
 |  u8   shift                          |  anchor shift to compute where the input to compare
 |  cmp_bytes[L]                        |  bytes used for compare
 +--------------------------------------+
 | next_record = current + 8 + L        |
 +--------------------------------------+
 ```

For example, a pattern that's decompiled and represented to JSON look like this
 ```
 "29340": {
      "leaf_pattern_record_id": 29340,
      "shift": 5,
      "length": 18,
      "match_type": "exact",
      "wildcard_constant_db": 0,
      "compare_bytes_db_hex": "c1c0ddc9ccc78bc4d5d5c9ccc6c4d1cccacb",
      "expected_positions": ["0x64", "0x65", "0x78", ... , "0x6E"],
      "wildcard_positions": []
    }
 ```

### RE result (3): STRING_GROUPS_BLOB

- **STRING_GROUPS_BLOB**: Module name is called `e2p`. The result of how many times a leaf (from kb10) hits will be mapped into each `e2p` promotion slot (via `nq3` mapping block). The leaf-hit result is represented as a counter. If one leaf appears in a scan block means counter increases by 1, regardless of how many times a leaf appears. A slot is promoted when `counter >= threshold(slot)`. Promotion means the file is considered malicious. The name of malware is gonna be mapped from NamePool later.

 String group blob (multi_string / e2p) (fixed 3 blocks)

 ```
 +---------------------------+
 | NQ3 block A               |  u32 b, u32 c, u32 a_len, a_bytes[a_len]
 +---------------------------+
 | NQ3 block B               |  (mapping leaf -> group)
 +---------------------------+
 | NQ3 block C               |  (threshold / promotion)
 +---------------------------+
 ```

## Avast scanning

1. IO processing
- Select file / memory to scan
- Decompress or unpack if required
- Select scan regions

2. Scan (filter)
- Select proper database set by content type (dex type for Java bytecode, ELFA for ELF on ARM)
- Use bloom filter as fast reject stage
- If bloom says possible hit, continue to group routing
- Group routing computes bucket/group index from hash-derived values; then select group records to obtain candidate pattern route metadata

3. Scan (signatures matching)
- Use signature from each record (leaf) to find data from input depends on mode, shift, ... `[match_result] = ([input_data] == [pattern] ^ 0xA5)`
- Map leaf hits into group counters through mapping blocks.
- If `counter >= threshold`, the file is considered infected / malicious
- Resolve NamePool from result to show human-readable malware names

## How to use the tool suite

The tool **DOES NOT** contain database from Avast mobile nor its decompiled result. Reseacher can download apk file then extract data. Version `26.2.2.260304121` was used to test this tool suite.
(The file `pyproject.toml` is useless. It was generated by Cursor so I just leave it there.)

This tool suite contains 3 tools.
1. `rule_decompiler.py`: read database and decompile to human-readable JSON format.
2. `explain_rule.py`: show rule info from id, or show pseudo Yara-like format.
3. `scanner.py`: Simulate the scan progress. It has option `--debug` to show some debug information.

### Decompile database

This tool requires `--assets-dir`, which points to the folder that contains database files `db_dex.map`, `db_elfa.map`, `db_dex.nmp`, `db_elfa.nmp`. It writes decompiled database files to `--out-dir`.
 For example: `python3 rule_decompiler.py --assets-dir assets --out-dir decompiled_db` will show:

```
[+] db_dex -> decompiled_db
[+] db_elfa -> decompiled_db

[summary] decompile results
  databases: 2
  total_name_pool_count: 9948
  total_leaf_count: 31070
  total_group_count: 9948
  section_counter_payload_total_bytes:
    [STRINGS_BLOB]: 1204745
    [STRING_GROUPS_BLOB]: 82744
```

Results should be saved in `decompiled_db`

```
$ls decompiled_db
total 28M
-rw-rw-r-- 1 dmknght dmknght  22M Mar 27 17:26 DEX_leaf_signatures.json
-rw-rw-r-- 1 dmknght dmknght 4.0M Mar 27 17:26 DEX_name_pool.json
-rw-rw-r-- 1 dmknght dmknght 1.5M Mar 27 17:26 ELFA_leaf_signatures.json
-rw-rw-r-- 1 dmknght dmknght 319K Mar 27 17:26 ELFA_name_pool.json
```

### Find and read information about a signature.

This tool reads from JSON files and shows information that helps reseacher understand the database easier. For example, researcher can search information about Mirai malware: `python3 explain_rule.py --rules-dir decompiled_db -f Mirai`

The output result is rather long. Here's just a few:
```
rules_set='ELFA'	group_idx=242	name_id=241	threshold=2	leaves=[636, 637]	'ELF:Mirai-UD [Trj]'
rules_set='ELFA'	group_idx=243	name_id=242	threshold=2	leaves=[638, 639]	'ELF:Mirai-UF [Trj]'
rules_set='ELFA'	group_idx=244	name_id=243	threshold=1	leaves=[642]	'ELF:Mirai-UM [Trj]'
rules_set='ELFA'	group_idx=245	name_id=244	threshold=1	leaves=[634]	'ELF:Mirai-TT [Trj]'
rules_set='ELFA'	group_idx=246	name_id=245	threshold=1	leaves=[633]	'ELF:Mirai-TQ [Trj]'
```

From the result, we can assume `ELF:Mirai-UD [Trj]` uses 2 patterns (with id `636` and `637`). Its name_id is `241`. Show we can ask the tool to show us the detection logic: `python3 explain_rule.py --rules-dir decompiled_db --show-name-id 241 --engine ELFA`. The result is rather long, so I only show some important parts

```
"name": "ELF:Mirai-UD [Trj]",
    "threshold": 2,
    "required_leaf_increments": [
      [
        636,
        1
      ],
      [
        637,
        1
      ]
    ],
    "promotion_expression": "(hit(636) + hit(637)) >= 2"
...
        "leaf_pattern_record_id": 636,
        "shift": 4,
        "length": 8,
        "match_type": "exact",
        "wildcard_constant_db": 0,
        "compare_bytes_db_hex": "8acdd0c4d2c0cc9e",
        "compare_bytes_real_hex": "2f6875617765693b",
...
        "leaf_pattern_record_id": 637,
        "shift": 10,
        "length": 15,
        "match_type": "exact",
        "wildcard_constant_db": 0,
        "compare_bytes_db_hex": "c0c6cdca85edf0e4f2e0ecf0f5ebf5",
        "compare_bytes_real_hex": "6563686f2048554157454955504e50",
```

The value of `compare_bytes_db_hex` is the value from the database. the `compare_bytes_real_hex` is the actual value to compare (after XOR with `0xA5`). So the value of leaf `637` is actually the string `echo HUAWEIUPNP` and value of leaf `636` is `/huawei;`. But it looks rather confusing. That's why I told Cursor to create Yara-like syntax for easier understanding the logic. `python3 explain_rule.py --rules-dir decompiled_db --yara-name-id 241 --engine ELFA`. The tool gives:

```
// YARA-like rule: strings are hex; condition is pseudo promotion logic.
// Each leaf_x is boolean-like (0/1): matched at least once => 1, else 0.
rule ELFMirai_UD_Trj {
  meta:
    malware_name = "ELF:Mirai-UD [Trj]"
    <.. other metadata ..>
  strings:
    $leaf_636 = { 2F 68 75 61 77 65 69 3B }
    $leaf_637 = { 65 63 68 6F 20 48 55 41 57 45 49 55 50 4E 50 }
  condition:
    (leaf_636 + leaf_637) >= 2
}
```

It looks quite easy to understand, isn't it. But to make sure the logic is correct, we can play with the binary to see the actual result (and make sure we are not being fooled by LLM). But let's take a look at the scanner first.

### Simulate scan with scanner

This tool is a copied version from original Java code. If LLM didn't do slop things, we would have technically a scanning engine with Python code. That means we can do anything like debug to see how it works. Like the decompiler tool, this one requires an asset directory, which contains database of Avast on Android: `python3 scanner.py --assets-dir assets --scan-file /usr/bin/ls`. The output shows... nothing, which is accurate because this file shouldn't contain any malware. But we can add `--debug`, which Cursor nicely added some debug messages to see how this engine works.

```
[debug] kb10 scan (ELFA / db_elfa / db_elfa.map)
  input_file: /usr/bin/ls
  file_size_bytes: 158632  scan_cap: 8388608  effective_scan_len: 158632
  kb10: scan_buffer_len=158632  scan_limit_from_map=124  n2=158628  n3_phase1_last_n_cur=124
  kb10: bloom_len=4096 B  group_filter_len=16384 B
  phases: phase1_positions=125  phase2_positions=158380  phase3_positions=124  total_n_cur=158629
  bloom: pass=6218  miss=152411  bad_index=0
  u32_gate: pass=56  miss=6162  read_bounds_fail=0
  PatternC: compare_try=107  compare_hit=16
  results: raw_match_tuples=16  unique_pattern_record_ids=15
  PatternC hits (raw file bytes at input_start_offset; XOR 0xA5 applied in engine, not in hex):
    #1  pattern_record_id=51  kb10_anchor=4683  input_start_offset=4683  compare_len=6  mode=exact
         hex: 737472637079
    #2  pattern_record_id=111  kb10_anchor=5106  input_start_offset=5104  compare_len=6  mode=exact
         hex: 6d656d637079
    #3  pattern_record_id=143  kb10_anchor=5565  input_start_offset=5563  compare_len=6  mode=exact
         hex: 66636c6f7365
    #4  pattern_record_id=100  kb10_anchor=5572  input_start_offset=5570  compare_len=6  mode=exact
         hex: 6d656d736574
    #5  pattern_record_id=101  kb10_anchor=5584  input_start_offset=5584  compare_len=4  mode=exact
         hex: 70757473
    #6  pattern_record_id=813  kb10_anchor=5654  input_start_offset=5652  compare_len=12  mode=exact
         hex: 736967656d70747973657400
    #7  pattern_record_id=111  kb10_anchor=5674  input_start_offset=5672  compare_len=6  mode=exact
         hex: 6d656d637079
    #8  pattern_record_id=65  kb10_anchor=5907  input_start_offset=5904  compare_len=7  mode=exact
         hex: 6c6962632e736f
    #9  pattern_record_id=106  kb10_anchor=115119  input_start_offset=115119  compare_len=4  mode=exact
         hex: 70697065
    #10  pattern_record_id=1379  kb10_anchor=120451  input_start_offset=120451  compare_len=6  mode=exact
         hex: 7368656c6c00
    #11  pattern_record_id=94  kb10_anchor=156420  input_start_offset=156417  compare_len=10  mode=exact
         hex: 2e736873747274616200
    #12  pattern_record_id=39  kb10_anchor=156486  input_start_offset=156483  compare_len=7  mode=exact
         hex: 2e64796e73796d
    #13  pattern_record_id=8  kb10_anchor=156574  input_start_offset=156574  compare_len=7  mode=exact
         hex: 2e726f64617461
    #14  pattern_record_id=1  kb10_anchor=156622  input_start_offset=156620  compare_len=11  mode=exact
         hex: 2e696e69745f6172726179
    #15  pattern_record_id=77  kb10_anchor=156637  input_start_offset=156632  compare_len=11  mode=exact
         hex: 2e66696e695f6172726179
    #16  pattern_record_id=55  kb10_anchor=156659  input_start_offset=156657  compare_len=8  mode=exact
         hex: 2e64796e616d6963
[debug] promotion: engine_type='MULTI_STRING'  leaf_pattern_ids_count=15  promoted_name_pool_ids=0
[debug] ========== final verdict (this engine / map) ==========
  map_engine_type: 'MULTI_STRING'  (db_elfa.map)
  kb10: leaf pattern_record_id hit(s) (unique): [1, 8, 39, 51, 55, 65, 77, 94, 100, 101, 106, 111, 143, 813, 1379]
  promotion (e2p): counters per map slot idx fed by E2pAIter from leaf hits; emit NamePool id (idx-1) when counter != 0 and counter >= threshold(idx) and threshold != 0.
  e2p slots with non-zero counter after scan:
    slot_idx=374  counter=1  threshold=2  would_promote=False  name_pool_id_if_promoted=373
    slot_idx=466  counter=1  threshold=3  would_promote=False  name_pool_id_if_promoted=465
    slot_idx=767  counter=3  threshold=10  would_promote=False  name_pool_id_if_promoted=766
    slot_idx=811  counter=3  threshold=7  would_promote=False  name_pool_id_if_promoted=810
    slot_idx=884  counter=3  threshold=10  would_promote=False  name_pool_id_if_promoted=883
    slot_idx=885  counter=3  threshold=9  would_promote=False  name_pool_id_if_promoted=884
    slot_idx=1044  counter=1  threshold=4  would_promote=False  name_pool_id_if_promoted=1043
    slot_idx=1048  counter=1  threshold=10  would_promote=False  name_pool_id_if_promoted=1047
    slot_idx=1054  counter=2  threshold=8  would_promote=False  name_pool_id_if_promoted=1053
    slot_idx=1067  counter=1  threshold=7  would_promote=False  name_pool_id_if_promoted=1066
  detected malware name(s): (none) — no e2p slot satisfied threshold, or NamePool decode failed.
  conclusion: kb10 matched substring(s) but MULTI_STRING rule set did not promote to a final name.
```

Technically, there were some strings appeared in the `/usr/bin/ls`. However, the `hits` counter didn't match the threshold, hence no malware detected. So if we add the strings `6563686f2048554157454955504e50` and `2f6875617765693b` to the binary file, it should be detected as malware, shouldn't it? We can use `xxd` and `dd` to modify bytes on file with command `echo "$HEX_VALUE" | xxd -r -p | dd of="$TARGET_BIN" bs=1 seek=$OFFSET conv=notrunc status=none`

```
mkdir payload
cp /usr/bin/ls payload
echo "6563686f2048554157454955504e50" | xxd -r -p | dd of="payload/ls" bs=1 seek=50 conv=notrunc status=none
echo "2f6875617765693b" | xxd -r -p | dd of="payload/ls" bs=1 seek=195 conv=notrunc status=none
python3 scanner.py --assets-dir assets --scan-file payload/ls --debug
```

To my surprise, the string `2f6875617765693b` did not appear in the `PatternC` hits step. It was likely filtered by the bloom filter or the group filter. Does this mean the tool suite does not work and the project is still AI slop? Well I decided to take another route. Using `python3 explain_rule.py --rules-dir decompiled_db --engine ELFA -f Mirai`, we can see there are multiple signatures that requires only 1 string:

```
rules_set='ELFA'	group_idx=995	name_id=994	threshold=1	leaves=[1008]	'ELF:MiraiDownloader-JM [Drp]'
rules_set='ELFA'	group_idx=1014	name_id=1013	threshold=1	leaves=[1706]	'ELF:Mirai-DCX [Bot]'
```

The logic of rule `994` is:
```
$python3 explain_rule.py --rules-dir decompiled_db --engine ELFA --yara-name-id 994
// YARA-like rule: strings are hex; condition is pseudo promotion logic.
// Each leaf_x is boolean-like (0/1): matched at least once => 1, else 0.
rule ELFMiraiDownloader_JM_Drp {
  meta:
    malware_name = "ELF:MiraiDownloader-JM [Drp]"
    name_id = 994
    group_idx = 995
    rules_set = 'ELFA'
    engine = 'ELFA'
    engine_type = 'MULTI_STRING'
    db_shifts_hex_unique = ['0x04']
    db_lengths_unique = [14]
    kb10_ref = "leaf_signatures.json: kb10.*"
  strings:
    $leaf_1008 = { 47 45 54 20 2F 75 7A 64 61 64 2E 61 72 6D }
  condition:
    leaf_1008
}
```

That means we can use the string `474554202F757A6461642E61726D` to trigger detection. I created a new test case:

```
cp /usr/bin/ls payload
echo "474554202F757A6461642E61726D" | xxd -r -p | dd of="payload/ls" bs=1 seek=150 conv=notrunc status=none
```

The result is as expected

```
$python3 scanner.py --assets-dir assets --scan-file payload/ls --debug

...
slot_idx=995  counter=1  threshold=1  would_promote=True  name_pool_id_if_promoted=994
...
  detected malware name(s): ['ELF:MiraiDownloader-JM [Drp]']
  conclusion: at least one e2p slot reached threshold → name(s) from NamePool.
ELF:MiraiDownloader-JM [Drp]
```

But, how about scanning with Virustotal? File that has hash `a38c9e40fc1d22aeeb11cd6fbd34393665e487712a08f501dd228c1b81e2968a` is detected as `Avast-Mobile ELF:MiraiDownloader-JM [Drp]` (see:
`https://www.virustotal.com/gui/file/a38c9e40fc1d22aeeb11cd6fbd34393665e487712a08f501dd228c1b81e2968a?nocache=1`)

False positives are even worse. In tests I ran before writing this README, some samples were detected by multiple engines:

- The first one`https://www.virustotal.com/gui/file/7165771959c49ad1a47c08afcb52ce2d90781ea550756f0884b8ed325deb4777?nocache=1`

```
5/65 security vendors flagged this file as malicious
Last Analysis Date 4 days ago (since I copied the result)
7165771959c49ad1a47c08afcb52ce2d90781ea550756f0884b8ed325deb4777
payload.elf

Antiy-AVL Trojan/Linux.Mirai.b
Avast ELF:Mirai-TO [Trj]
Avast-Mobile ELF:Mirai-VK [Trj]
AVG ELF:Mirai-TO [Trj]
Cynet Malicious (score: 99)
```

- Second one: `https://www.virustotal.com/gui/file/7c1dc658f510c4659d94c0257c129bb47dc0461f4bcb3dfecb1dbd86030cad61?nocache=1`

```
9/61 security vendors flagged this file as malicious
Last Analysis Date 11 minutes ago (Rescanned before copying the result)
7c1dc658f510c4659d94c0257c129bb47dc0461f4bcb3dfecb1dbd86030cad61 payload.elf

AliCloud Trojan:Android/AVE.Gdjzzj
Avast-Mobile ELF:Gafgyt-D [Trj]
Avira (no cloud) ANDROID/AVE.Gafgyt.ulkli
Cynet Malicious (score: 99)
Fortinet PossibleThreat
GData Linux.Trojan.Agent.LZTXPH
Google Detected
Ikarus AVE.AndroidOS.Gafgyt
WithSecure Malware.ANDROID/AVE.Gafgyt.ulkli
```


