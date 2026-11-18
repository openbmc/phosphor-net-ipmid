#include "command/rakp_setup_check.hpp"

#include <ipmid/sessiondef.hpp>

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

using command::rakp1AllowedForState;
using command::rakp1RequesterMatches;
using command::rakp3AllowedForState;

// Regression test for the RAKP Message 1 relabeling CVE.
//
// RAKP Message 1 (re-)derives a session's identity and privilege. Before the
// fix, RAKP Message 1 was accepted regardless of session state, so an attacker
// who knew the BMC session ID could send a second RAKP Message 1 against an
// already-authenticated (active) session and relabel its identity/privilege.
// The guard below is the check RAKP12() consults before touching any identity
// state; these tests ensure only setupInProgress sessions may process it.

TEST(RAKP1SetupGuard, ActiveSessionRejectsRakp1)
{
    // The core of the CVE: a fully authenticated, active session must NOT be
    // allowed to process another RAKP Message 1 (which would relabel it).
    EXPECT_FALSE(
        rakp1AllowedForState(static_cast<uint8_t>(session::State::active)));
}

TEST(RAKP1SetupGuard, OnlySetupInProgressAllowsRakp1)
{
    // A session still being set up is the only state that may process RAKP1.
    EXPECT_TRUE(rakp1AllowedForState(
        static_cast<uint8_t>(session::State::setupInProgress)));

    // Every non-setup state must reject RAKP Message 1.
    EXPECT_FALSE(
        rakp1AllowedForState(static_cast<uint8_t>(session::State::inactive)));
    EXPECT_FALSE(rakp1AllowedForState(
        static_cast<uint8_t>(session::State::tearDownInProgress)));
}

// Regression test for the RAKP Message 3 stale-state authentication bypass
//
// Every early-return error path in RAKP Message 1 (for example a request for
// CALLBACK privilege) returns before the per-account user key and a fresh BMC
// random number are committed to the authentication algorithm, leaving stale
// or default key material behind. Before the fix, RAKP Message 3 validated
// against whatever state was present, so an attacker could activate a session
// without a valid password. RAKP Message 3 must only be processed for a
// session still in setup (and, in RAKP34(), only when rakp2Committed is set).

TEST(RAKP3SetupGuard, OnlySetupInProgressAllowsRakp3)
{
    // A session still being set up is the only state that may process RAKP3.
    EXPECT_TRUE(rakp3AllowedForState(
        static_cast<uint8_t>(session::State::setupInProgress)));

    // An already-active session must not re-process RAKP Message 3.
    EXPECT_FALSE(
        rakp3AllowedForState(static_cast<uint8_t>(session::State::active)));

    // Every other non-setup state must reject RAKP Message 3.
    EXPECT_FALSE(
        rakp3AllowedForState(static_cast<uint8_t>(session::State::inactive)));
    EXPECT_FALSE(rakp3AllowedForState(
        static_cast<uint8_t>(session::State::tearDownInProgress)));
}

TEST(RAKP1SetupGuard, RequesterTupleMustMatch)
{
    const std::string addr = "10.0.0.5";

    // An identical source tuple is accepted (legitimate RAKP1 / retransmit).
    EXPECT_TRUE(rakp1RequesterMatches(true, addr, 1234, addr, 1234));

    // A RAKP Message 1 injected from a different source address is rejected.
    EXPECT_FALSE(rakp1RequesterMatches(true, addr, 1234, "10.0.0.6", 1234));

    // A RAKP Message 1 injected from a different source port is rejected.
    EXPECT_FALSE(rakp1RequesterMatches(true, addr, 1234, addr, 4321));
}

TEST(RAKP1SetupGuard, UnboundRequesterAllowed)
{
    // If no requester tuple has been bound yet, there is nothing to compare
    // against and the check does not block.
    EXPECT_TRUE(rakp1RequesterMatches(false, "", 0, "10.0.0.6", 4321));
}
