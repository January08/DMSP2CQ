#ifndef TIME_H
#define TIME_H

#include <chrono>

class Timer
{
    private:
        using milliseconds_ratio = std::ratio<1, 1000>;
        using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

        std::chrono::_V2::system_clock::time_point m_Start;

    public:
        Timer()
        {
            m_Start = std::chrono::system_clock::now();
        }

        void start()
        {
            m_Start = std::chrono::system_clock::now();
        }

        double end()
        {
            duration_millis duration=std::chrono::system_clock::now()-m_Start;
            return duration.count();
        }
};

#endif