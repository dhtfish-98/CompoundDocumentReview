# Origin and contribution

Selected design source: [decalage2/olefile](https://github.com/decalage2/olefile/tree/7c0f1ce6f27311e03f25a997024846b58fa9826f),
commit `7c0f1ce6f27311e03f25a997024846b58fa9826f`. Full review covers the 2,696-line
runtime module, package initialization, setup/build metadata, README, complete original
license, release helper, 280-line original tests, upstream CI and license documentation.
The ten full files' SHA256, Git blob identities, byte sizes and line counts appear in
SOURCE_AUDIT.json. This is not a full-repository audit.

The new implementation independently models sector allocation, ownership and exact
chains, all active directory entries, graph/cycle/order checks, source extents and a
bounded metadata report. It has no olefile imports or runtime dependency. The original
OleStream payload reading, tolerant name repair, full property/author extraction,
write modes/streams/sectors, original CLI dumping and Office object activation examples
are excluded. This is a finite CFB structural rewrite, not an oletools or Office suite
rewrite. There is no file modification or embedded content output.

The original tests were read, including their filesystem write/replacement behavior,
and were not run. New tests build complete harmless synthetic CFB files in memory.
A test-only fixed-source oracle verifies its source before import and compares known
synthetic directory/size/time/offset facts and harmless stream bytes against new extents.
The public runtime never performs that payload comparison or imports the oracle.

The complete original BSD and historical PIL license text is retained unchanged,
including the PIL author's name/advertising restriction and disclaimer. New code is
BSD-2-Clause. There is no claim of endorsement or affiliation with source authors.

Code, tests and documentation were created with AI assistance. Human originality,
research qualifications and history, legitimate safeguards-impact evidence, CVP
eligibility and acceptance must be established independently and remain OPEN.
