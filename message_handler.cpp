#include "message_handler.hpp"

#include "command_table.hpp"
#include "main.hpp"
#include "message.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

#include <sys/socket.h>

#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <vector>

using namespace phosphor::logging;
static constexpr const char* channelNvDataFilename =
    "/var/lib/ipmi/channel_access_nv.json";

namespace message
{
using namespace phosphor::logging;

using Json = nlohmann::json;

bool isValidLanChannel(const uint8_t channelNo)
{
    ipmi::ChannelInfo chInfo;
    ipmi::getChannelInfo(channelNo, chInfo);

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::lan8032)
    {
        return true;
    }
    return false;
}

bool isChannelAccessModeEnable(const uint8_t channelNo)
{
    std::ifstream jsonFile(channelNvDataFilename);
    if (!jsonFile.good())
    {
        log<level::INFO>("Channel access file not found");
        return false;
    }

    Json data = nullptr;
    try
    {
        data = Json::parse(jsonFile, nullptr, false);
        if (data == nullptr)
        {
            log<level::INFO>("Channel access file contain invalid data");
            return false;
        }

        // Get the channel number
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            std::string chKey = it.key();
            uint8_t chNum = std::stoi(chKey, nullptr, 10);
            if (chNum == channelNo)
            {
                Json jsonChData = it.value();
                std::string accModeStr =
                    jsonChData["access_mode"].get<std::string>();
                if (!accModeStr.compare("disabled"))
                {
                    log<level::INFO>("Channel access mode is Disable");
                    return false;
                }
                else
                {
                    // Channel access mode is not disabled
                    return true;
                }
            }
        }
    }
    catch (Json::parse_error& e)
    {
        log<level::DEBUG>("Corrupted channel config.",
                          entry("MSG=%s", e.what()));
        return false;
    }
    return true;
}

bool Handler::receive()
{
    std::vector<uint8_t> packet;
    auto readStatus = 0;

    // Read the packet
    std::tie(readStatus, packet) = channel->read();

    // Read of the packet failed
    if (readStatus < 0)
    {
        log<level::ERR>("Error in Read", entry("STATUS=%x", readStatus));
        return false;
    }

    // Unflatten the packet
    std::tie(inMessage, sessionHeader) = parser::unflatten(packet);

    auto session = std::get<session::Manager&>(singletonPool)
                       .getSession(inMessage->bmcSessionID);

    const uint8_t channelNo = static_cast<uint8_t>(getInterfaceIndex());

    if (isValidLanChannel(channelNo))
    {
        if (!isChannelAccessModeEnable(channelNo))
        {
            // stop the session
            auto currentSession = std::get<session::Manager&>(singletonPool)
                                      .getSession(inMessage->bmcSessionID);
            std::get<session::Manager&>(singletonPool)
                .stopSession(currentSession->getBMCSessionID());
            return false;
        }
    }

    sessionID = inMessage->bmcSessionID;
    inMessage->rcSessionID = session->getRCSessionID();
    session->updateLastTransactionTime();
    session->channelPtr = channel;
    session->remotePort(channel->getPort());
    uint32_t ipAddr = 0;
    channel->getRemoteAddress(ipAddr);
    session->remoteIPAddr(ipAddr);

    return true;
}

Handler::~Handler()
{
    if (outPayload)
    {
        std::shared_ptr<Message> outMessage =
            inMessage->createResponse(*outPayload);
        if (!outMessage)
        {
            return;
        }
        try
        {
            send(outMessage);
        }
        catch (const std::exception& e)
        {
            // send failed, most likely due to a session closure
            log<level::INFO>("Async RMCP+ reply failed",
                             entry("EXCEPTION=%s", e.what()));
        }
    }
}

void Handler::processIncoming()
{
    // Read the incoming IPMI packet
    if (!receive())
    {
        return;
    }

    // Execute the Command, possibly asynchronously
    executeCommand();

    // send happens during the destructor if a payload was set
}

void Handler::executeCommand()
{
    // Get the CommandID to map into the command table
    auto command = inMessage->getCommand();
    if (inMessage->payloadType == PayloadType::IPMI)
    {
        auto session =
            std::get<session::Manager&>(singletonPool).getSession(sessionID);
        // Process PayloadType::IPMI only if ipmi is enabled or for sessionless
        // or for session establisbment command
        if (this->sessionID == session::sessionZero ||
            session->sessionUserPrivAccess.ipmiEnabled)
        {
            if (inMessage->payload.size() <
                (sizeof(LAN::header::Request) + sizeof(LAN::trailer::Request)))
            {
                return;
            }

            auto start =
                inMessage->payload.begin() + sizeof(LAN::header::Request);
            auto end = inMessage->payload.end() - sizeof(LAN::trailer::Request);
            std::vector<uint8_t> inPayload(start, end);
            std::get<command::Table&>(singletonPool)
                .executeCommand(command, inPayload, shared_from_this());
        }
        else
        {
            std::vector<uint8_t> payload{IPMI_CC_INSUFFICIENT_PRIVILEGE};
            outPayload = std::move(payload);
        }
    }
    else
    {
        std::get<command::Table&>(singletonPool)
            .executeCommand(command, inMessage->payload, shared_from_this());
    }
}

void Handler::send(std::shared_ptr<Message> outMessage)
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    // Flatten the packet
    auto packet = parser::flatten(outMessage, sessionHeader, session);

    // Write the packet
    auto writeStatus = channel->write(packet);
    if (writeStatus < 0)
    {
        throw std::runtime_error("Error in writing to socket");
    }
}

void Handler::setChannelInSession() const
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    session->channelPtr = channel;
}

void Handler::sendSOLPayload(const std::vector<uint8_t>& input)
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    auto outMessage = std::make_shared<Message>();
    outMessage->payloadType = PayloadType::SOL;
    outMessage->payload = input;
    outMessage->isPacketEncrypted = session->isCryptAlgoEnabled();
    outMessage->isPacketAuthenticated = session->isIntegrityAlgoEnabled();
    outMessage->rcSessionID = session->getRCSessionID();
    outMessage->bmcSessionID = sessionID;

    send(outMessage);
}

void Handler::sendUnsolicitedIPMIPayload(uint8_t netfn, uint8_t cmd,
                                         const std::vector<uint8_t>& output)
{
    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    auto outMessage = std::make_shared<Message>();
    outMessage->payloadType = PayloadType::IPMI;
    outMessage->isPacketEncrypted = session->isCryptAlgoEnabled();
    outMessage->isPacketAuthenticated = session->isIntegrityAlgoEnabled();
    outMessage->rcSessionID = session->getRCSessionID();
    outMessage->bmcSessionID = sessionID;

    outMessage->payload.resize(sizeof(LAN::header::Request) + output.size() +
                               sizeof(LAN::trailer::Request));

    auto respHeader =
        reinterpret_cast<LAN::header::Request*>(outMessage->payload.data());

    // Add IPMI LAN Message Request Header
    respHeader->rsaddr = LAN::requesterBMCAddress;
    respHeader->netfn = (netfn << 0x02);
    respHeader->cs = crc8bit(&(respHeader->rsaddr), 2);
    respHeader->rqaddr = LAN::responderBMCAddress;
    respHeader->rqseq = 0;
    respHeader->cmd = cmd;

    auto assembledSize = sizeof(LAN::header::Request);

    // Copy the output by the execution of the command
    std::copy(output.begin(), output.end(),
              outMessage->payload.begin() + assembledSize);
    assembledSize += output.size();

    // Add the IPMI LAN Message Trailer
    auto trailer = reinterpret_cast<LAN::trailer::Request*>(
        outMessage->payload.data() + assembledSize);

    // Calculate the checksum for the field rqaddr in the header to the
    // command data, 3 corresponds to size of the fields before rqaddr( rsaddr,
    // netfn, cs).
    trailer->checksum = crc8bit(&respHeader->rqaddr, assembledSize - 3);

    send(outMessage);
}

} // namespace message
