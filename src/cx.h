#pragma once

namespace cx {
    constexpr int char_to_int(const char& ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';

        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;

        return ch - 'a' + 10;
    };

    template <typename T, T F = 16>
    constexpr auto concate_hex(const T& a, const T& b) {
        return T(F) * a + b;
    }

    template <size_t N>
    struct str_to_ba {
        std::array<char, N> str{};

        constexpr str_to_ba(const char* a) noexcept {
            for (size_t i = 0u; i < N; ++i) {
                str[i] = a[i];
            }
        }

        constexpr auto size() const {
            return N;
        }
    };

    template <size_t N>
    str_to_ba(const char(&)[N])->str_to_ba<N - 1>;

    template <str_to_ba str>
    constexpr auto s_to_ba() {
        static_assert((str.size() / 2) % 2 == 0);

        std::array<uint8_t, str.size() / 2> result{};

        size_t at = 0;
        bool skip_next_char = false;


        for (size_t i = 0u; i < str.size(); ++i) {
            // skip next char
            if (skip_next_char) {
                skip_next_char = false;
                continue;
            }

            if (i + 1 < str.size()) {
                result[at] = concate_hex<int>(char_to_int(str.str[i]), char_to_int(str.str[i + 1]));
                ++at;

                skip_next_char = true;
            }
        }

        return result;
    }
}