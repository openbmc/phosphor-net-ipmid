#pragma once

#include <algorithm>
#include <deque>
#include <vector>

namespace sol
{

using ConsoleBuffer = std::deque<uint8_t>;
using Buffer = std::vector<uint8_t>;

/** @class ConsoleData
 *
 *  The console data is the buffer that holds the data that comes from the host
 *  console which is to be sent to the remote console. The buffer is needed due
 *  to the latency with the IPMI remote client. The current support for the
 *  buffer is to support one instance of the SOL payload.
 */
class ConsoleData
{
    public:
        /** @brief Get the current size of the host console buffer.
         *
         *  @return size of the host console buffer.
         */
        size_t size() const
        {
            return data.size();
        }

        /** @brief Read host console data.
         *
         *  This API would read the host console data based on the requested
         *  size, if the buffer size is less than the requested, then the
         *  available data is returned. The data is read from the beginning of
         *  the buffer.
         *
         *  @param[in] size - requested number of bytes.
         *
         *  @return buffer containing host console data.
         */
        std::vector<uint8_t> read(size_t size) const
        {
            Buffer response(std::min(data.size(), size));
            std::copy_n(data.begin(), response.size(), response.data());
            return response;
        }

        /** @brief Write host console data.
         *
         *  This API would append the input data to the host console buffer.
         *
         *  @param[in] input - data to be written to the console buffer.
         */
        void write(const Buffer& input)
        {
            data.insert(data.end(), input.begin(), input.end());
        }

        /** @brief Erase console buffer.
         *
         *  @param[in] size - the number of bytes to be erased from the console
         *                    buffer.
         *
         *  @note If the console buffer has less bytes that that was requested,
         *        then the available size is erased.
         */
        void erase(size_t size)
        {
            data.erase(data.begin(), data.begin() + std::min(data.size(),
                       size));
        }

    private:

        /** @brief Storage for host console data. */
        ConsoleBuffer data;
};

} // namespace sol
