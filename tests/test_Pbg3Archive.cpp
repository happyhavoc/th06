#include <fstream>
#include <vector>

#include "pbg3/Pbg3Archive.hpp"
#include <munit.h>

static MunitResult test_read_raw(const MunitParameter params[], void *user_data)
{
    Pbg3Archive archive;
    munit_assert_int(archive.Load("resources/KOUMAKYO_IN.dat"), !=, 0);

    // Read from PBG3
    i32 entryIdx = archive.FindEntry("th06logo.jpg");
    munit_assert_int(entryIdx, !=, -1);

    u32 size;
    u32 expectedCsum;
    u8 *entry = archive.ReadEntryRaw(&size, &expectedCsum, entryIdx);
    munit_assert_not_null(entry);

    return MUNIT_OK;
}

static MunitResult test_read_decompress(const MunitParameter params[], void *user_data)
{
    Pbg3Archive archive;
    munit_assert_int(archive.Load("resources/KOUMAKYO_IN.dat"), !=, 0);

    // Read from PBG3
    i32 entryIdx = archive.FindEntry("th06logo.jpg");
    munit_assert_int(entryIdx, !=, -1);
    u8 *entry = archive.ReadDecompressEntry(entryIdx, "th06logo.jpg");
    munit_assert_not_null(entry);
    u32 entrySize = archive.GetEntrySize(entryIdx);
    munit_assert_int(entrySize, !=, 0);

    // Write decompressed file to disk.
    std::ofstream outfile("resources/th06logo2.jpg.expected", std::ios::out | std::ios::binary);
    outfile.write((char *)entry, entrySize);

    // Read file on disk
    std::ifstream infile("resources/th06logo.jpg", std::ios::binary);
    std::vector<char> buffer(std::istreambuf_iterator<char>(infile), std::istreambuf_iterator<char>());
    u8 *reference = (u8 *)&buffer[0];
    u32 referenceSize = buffer.size();

    munit_assert_int(entrySize, ==, referenceSize);
    munit_assert_memory_equal(entrySize, entry, reference);
    return MUNIT_OK;
}

static MunitResult test_read_decompress_anm(const MunitParameter params[], void *user_data)
{
    Pbg3Archive archive;
    munit_assert_int(archive.Load("resources/KOUMAKYO_IN.dat"), !=, 0);

    // Read from PBG3
    i32 entryIdx = archive.FindEntry("text.anm");
    munit_assert_int(entryIdx, !=, -1);
    u8 *entry = archive.ReadDecompressEntry(entryIdx, "text.anm");
    munit_assert_not_null(entry);
    u32 entrySize = archive.GetEntrySize(entryIdx);
    munit_assert_int(entrySize, !=, 0);

    // Write decompressed file to disk.
    std::ofstream outfile("resources/text.anm.expected", std::ios::out | std::ios::binary);
    outfile.write((char *)entry, entrySize);

    // Read file on disk
    std::ifstream infile("resources/text.anm", std::ios::binary);
    std::vector<char> buffer(std::istreambuf_iterator<char>(infile), std::istreambuf_iterator<char>());
    u8 *reference = (u8 *)&buffer[0];
    u32 referenceSize = buffer.size();

    munit_assert_int(entrySize, ==, referenceSize);
    munit_assert_memory_equal(entrySize, entry, reference);
    return MUNIT_OK;
}

static MunitTest pbg3archives_test_suite_tests[] = {
    {"/read_decompress_anm", test_read_decompress_anm, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/read_decompress", test_read_decompress, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/read_raw", test_read_raw, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    /* Mark the end of the array with an entry where the test
     * function is NULL */
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
