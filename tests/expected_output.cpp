/*******************************************************************************
 *   (c) 2019 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <coin.h>
#include <fmt/core.h>

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "zxformat.h"
#include "zxmacros_x64.h"
const uint32_t fieldSize = 39;

// Helper function to safely get string from JSON value (handles both string and number types)
std::string getStringValue(const nlohmann::json &obj, const std::string &key, const std::string &defaultValue = "") {
    if (!obj.contains(key)) {
        return defaultValue;
    }
    if (obj[key].is_string()) {
        return obj[key].get<std::string>();
    } else if (obj[key].is_number()) {
        return std::to_string(obj[key].get<uint64_t>());
    }
    return defaultValue;
}

// Helper function to safely get uint64_t from JSON value
uint64_t getUint64Value(const nlohmann::json &obj, const std::string &key, uint64_t defaultValue = 0) {
    if (!obj.contains(key)) {
        return defaultValue;
    }
    if (obj[key].is_number()) {
        return obj[key].get<uint64_t>();
    } else if (obj[key].is_string()) {
        try {
            return std::stoull(obj[key].get<std::string>());
        } catch (...) {
            return defaultValue;
        }
    }
    return defaultValue;
}

template <typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&...args) {
    answer.push_back(fmt::format(format_str, args...));
}

std::vector<std::string> FormatEthAddress(const std::string &name, const uint32_t idx, const std::string &address) {
    auto answer = std::vector<std::string>();
    uint8_t numPages = 0;
    char outBuffer[100];

    pageString(outBuffer, fieldSize, address.c_str(), 0, &numPages);

    for (auto i = 0; i < numPages; i++) {
        MEMZERO(outBuffer, sizeof(outBuffer));
        pageString(outBuffer, fieldSize, address.c_str(), i, &numPages);

        auto pages = std::string("");

        if (numPages > 1) {
            pages = fmt::format("[{}/{}]", i + 1, numPages);
        }

        addTo(answer, "{} | {} {} : {}", idx, name, pages, outBuffer);
    }

    return answer;
}

std::string FormatAmount(const std::string &amount) {
    char buffer[500];
    MEMZERO(buffer, sizeof(buffer));
    fpstr_to_str(buffer, sizeof(buffer), amount.c_str(), COIN_AMOUNT_DECIMAL_PLACES);
    return std::string(buffer);
}

std::vector<std::string> EVMGenerateExpectedUIOutput(const nlohmann::json &json, bool) {
    auto answer = std::vector<std::string>();

    ///
    auto description = getStringValue(json, "description");
    auto message = json.value("message", nlohmann::json());
    auto receiver = getStringValue(message, "Receiver");
    auto contract = getStringValue(message, "Contract");
    auto amount = getStringValue(message, "Amount");
    auto nonce = getStringValue(message, "Nonce");
    auto maxFee = std::string();
    auto maxPriorityFee = std::string();
    auto gasPrice = std::string();
    if (description.find("eip1559") != std::string::npos) {
        maxFee = getStringValue(message, "MaxFeePerGas");
        maxPriorityFee = getStringValue(message, "MaxPriorityFeePerGas");
    } else {
        gasPrice = getStringValue(message, "GasPrice");
    }
    auto gasLimit = getStringValue(message, "GasLimit");
    auto value = getStringValue(message, "Value");
    auto txhash = getStringValue(message, "Eth-Hash");
    auto data = getStringValue(message, "Data");
    ///

    uint8_t idx = 0;
    auto destAddress = FormatEthAddress("Receiver", idx, receiver);
    answer.insert(answer.end(), destAddress.begin(), destAddress.end());

    idx++;
    auto contractAddress = FormatEthAddress("Contract", idx, contract);
    answer.insert(answer.end(), contractAddress.begin(), contractAddress.end());

    idx++;
    addTo(answer, "{} | Coin asset : {}", idx, "Flare");

    idx++;
    addTo(answer, "{} | Amount : {}", idx, amount);

    idx++;
    addTo(answer, "{} | Nonce : {}", idx, nonce);

    if (description.find("eip1559") != std::string::npos) {
        idx++;
        addTo(answer, "{} | Max Priority Fee : {}", idx, maxPriorityFee);
        idx++;
        addTo(answer, "{} | Max Fee : {}", idx, maxFee);
    }
    if (description.find("eip1559") == std::string::npos) {
        idx++;
        addTo(answer, "{} | Gas price : {}", idx, gasPrice);
    }

    idx++;
    addTo(answer, "{} | Gas limit : {}", idx, gasLimit);

    idx++;
    addTo(answer, "{} | Value : {}", idx, value);

    idx++;
    addTo(answer, "{} | Data : {}", idx, data);

    idx++;
    auto hash = FormatEthAddress("Eth-Hash", idx, txhash);
    answer.insert(answer.end(), hash.begin(), hash.end());

    return answer;
}
