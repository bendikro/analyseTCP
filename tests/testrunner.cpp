/* Generated file, do not edit */

#ifndef CXXTEST_RUNNING
#define CXXTEST_RUNNING
#endif

#define _CXXTEST_HAVE_STD
#include <cxxtest/TestListener.h>
#include <cxxtest/TestTracker.h>
#include <cxxtest/TestRunner.h>
#include <cxxtest/RealDescriptions.h>
#include <cxxtest/TestMain.h>
#include <cxxtest/ErrorPrinter.h>

int main( int argc, char *argv[] ) {
 int status;
    CxxTest::ErrorPrinter tmp;
    CxxTest::RealWorldDescription::_worldName = "cxxtest";
    status = CxxTest::Main< CxxTest::ErrorPrinter >( tmp, argc, argv );
    return status;
}
bool suite_TestSuite_init = false;
#include "TestAnalyseTCP.h"

static TestSuite suite_TestSuite;

static CxxTest::List Tests_TestSuite = { 0, 0 };
CxxTest::StaticSuiteDescription suiteDescription_TestSuite( "TestAnalyseTCP.h", 6, "TestSuite", suite_TestSuite, Tests_TestSuite );

static class TestDescription_suite_TestSuite_testAddition : public CxxTest::RealTestDescription {
public:
 TestDescription_suite_TestSuite_testAddition() : CxxTest::RealTestDescription( Tests_TestSuite, suiteDescription_TestSuite, 9, "testAddition" ) {}
 void runTest() { suite_TestSuite.testAddition(); }
} testDescription_suite_TestSuite_testAddition;

#include <cxxtest/Root.cpp>
const char* CxxTest::RealWorldDescription::_worldName = "cxxtest";
