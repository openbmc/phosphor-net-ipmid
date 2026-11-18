#pragma once

#include <ipmid/sessiondef.hpp>

#include <cstdint>
#include <string>

namespace command
{

/**
 * @brief Determine whether RAKP Message 1 may (re-)derive a session's identity.
 *
 * RAKP Message 1 begins the RMCP+ key-exchange for a session that is still
 * being set up. Once a session has become active, its identity (user name,
 * user id, channel/user privilege) is fixed for the life of the session.
 * Accepting another RAKP Message 1 on an active session would allow an
 * attacker who knows or guesses the BMC session ID to relabel the session's
 * identity or privilege. Only sessions in the setupInProgress state may
 * process RAKP Message 1.
 *
 * @param[in] sessionState - the current session::State value of the session
 *
 * @return true if RAKP Message 1 is permitted for this state, else false
 */
inline bool rakp1AllowedForState(uint8_t sessionState)
{
    return static_cast<session::State>(sessionState) ==
           session::State::setupInProgress;
}

/**
 * @brief Verify an incoming RAKP message originates from the console that
 *        opened the session.
 *
 * The session setup state is bound to the originating requester tuple: the
 * source IP address and port of the remote console that sent the Open Session
 * Request (the remote console and BMC session identifiers are already bound to
 * the session at creation time). An incoming RAKP message whose source tuple
 * differs from the bound tuple is rejected, preventing an attacker on a
 * different endpoint from hijacking or relabeling a session that is in setup.
 *
 * @param[in] bound     - whether a requester tuple has been bound to the
 *                        session yet
 * @param[in] boundAddr - source address bound at Open Session
 * @param[in] boundPort - source port bound at Open Session
 * @param[in] reqAddr   - source address of the incoming RAKP message
 * @param[in] reqPort   - source port of the incoming RAKP message
 *
 * @return true if the requester tuple matches (or none is bound yet), else
 *         false
 */
inline bool rakp1RequesterMatches(bool bound, const std::string& boundAddr,
                                  uint16_t boundPort,
                                  const std::string& reqAddr, uint16_t reqPort)
{
    if (!bound)
    {
        // No requester tuple has been bound yet; nothing to compare against.
        return true;
    }
    return boundAddr == reqAddr && boundPort == reqPort;
}

} // namespace command
