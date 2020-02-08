#ifndef PROGRAM_KEY_GENERATOR_HPP
#define PROGRAM_KEY_GENERATOR_HPP

#include <string>
#include <random>

#include <boost/date_time/posix_time/posix_time.hpp>

static inline std::string generate_key(int generate_len = 6, char start = ' ', char end = '~') {
    std::mt19937 generator{std::random_device{}()};
    std::uniform_int_distribution<int> distribution{start, end};

    std::string rand_str(generate_len, '\0');
    for (auto &dis: rand_str)
        dis = distribution(generator);
    return rand_str;
}

static inline boost::posix_time::ptime generate_expiration_timestamp() {
    static const int duration_in_days = 1;
    static const boost::posix_time::hours duration(duration_in_days * 24);
    boost::posix_time::ptime expiration_timestamp(boost::posix_time::second_clock::local_time() + duration);
    return expiration_timestamp;
}

#endif //PROGRAM_KEY_GENERATOR_HPP
