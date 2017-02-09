#pragma once

#include <algorithm>
#include <deque>
#include <vector>

namespace sol
{

using ConsoleBuffer = std::deque<uint8_t>;
using buffer = std::vector<uint8_t>;

class ConsoleData
{
    public:
        /**
         * @brief Get the current size of the host console buffer
         *
         * @return size of the host console buffer
         */
        auto getSize()
        {
            return data.size();
        }

        /**
         * @brief Read Host Console Data
         *
         * This API would read the host console data based on the requested
         * size, if the buffer size is less than the requested, then the
         * available data is returned. The data is read from the beginning of
         * the buffer.
         *
         * @param[in] size - requested number of bytes
         *
         * @return buffer containing host console data
         */
        auto readData(size_t size)
        {
            buffer response(std::min(data.size(), size));
            std::copy_n(data.begin(), response.size(), response.data());
            return response;
        }

        /**
         * @brief Write Host Console Data
         *
         * This API would append the input data to the host console buffer
         *
         * @param[in] input - data to be written to the console buffer
         */
        void writeData(const buffer& input)
        {
            data.insert(data.end(), input.begin(), input.end());
        }

        /**
         * @brief Erase console buffer
         *
         * @param[in] size - the number of bytes to be cleaned up
         *
         * @note If the console buffer has less bytes that that was requested,
         *       then the available size is erased.
         */
        void eraseBuffer(size_t size)
        {
            data.erase(data.begin(), data.begin() + std::min(data.size(),
                       size));
        }

    private:

        /** @brief Storage for host console data */
        ConsoleBuffer data;
};

} // namespace sol
