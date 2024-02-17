#include "munit.h"

#include "test_Pbg3Archive.cpp"

static MunitSuite root_test_suites[] = {
    {"/Pbg3Archives", pbg3archives_test_suite_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE},
    {NULL, NULL, NULL, 0, MUNIT_SUITE_OPTION_NONE}};
static const MunitSuite test_suite = {"", NULL, root_test_suites, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char **argv)
{
    /* Finally, we'll actually run our test suite!  That second argument
     * is the user_data parameter which will be passed either to the
     * test or (if provided) the fixture setup function. */
    return munit_suite_main(&test_suite, NULL, argc, argv);
}
