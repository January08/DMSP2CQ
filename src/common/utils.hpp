#ifndef UTILS_H
#define UTILS_H

#include <vector>

template <class T = std::vector<uint64_t>>
class globalData {
 private:
  std::vector<T> m_Data;
  std::mutex m;

 public:
  globalData(size_t n = 5) : m_Data(n) {}

  void add(const T &data, size_t pos) {
    std::lock_guard<std::mutex> lock(m);
    if (pos >= m_Data.size()) {
      m_Data.resize(pos + 1); 
    }
    m_Data[pos] = data;
  }

  T getByPos(size_t pos) {
    if (pos >= m_Data.size()) throw std::out_of_range("globalData out of range.");
    std::lock_guard<std::mutex> lock(m);
    return m_Data[pos];
  }

  void show(const std::string &str) {
    m.lock();
    std::cout << str << "\n";
    for (const auto &i : m_Data)
      for (const auto &j : i) std::cout << j << " ";
    std::cout << "\n";
    m.unlock();
  }

  std::vector<T> data() { return m_Data; }
  size_t size() { return m_Data.size(); }
  void set(const std::vector<T>& vec) { m_Data=vec; }
};

class globalFlag {
 private:
  uint64_t m_Flag;
  std::mutex m;

 public:
  globalFlag(uint64_t value = 0) : m_Flag(value) {}

  uint64_t get() { return m_Flag; }

  void reset(size_t value = 0) {
    m.lock();
    m_Flag = value;
    m.unlock();
  }

  uint64_t operator++(int) {
    uint64_t tmp;

    m.lock();
    tmp = m_Flag++;
    m.unlock();

    return tmp;
  }

  uint64_t operator--(int) {
    uint64_t tmp;

    m.lock();
    tmp = m_Flag--;
    m.unlock();

    return tmp;
  }
};
inline void waitFor(globalFlag& listenFlag,std::function<void(void)> funcOfSpecial,bool condition,size_t n)
{
  bool isSpec=condition?true:false;
  
  while(1)
  {
    bool shouldQuit=false;
    shouldQuit=listenFlag.get()==0&&!isSpec||listenFlag.get()==n&&isSpec?true:false;

    if(shouldQuit)
    {
      if(!isSpec)
        break;
      else
      {
        funcOfSpecial();
        listenFlag.reset(0);
        break;
      }
    }
    else
    {
      usleep(10);
    }
  }
}
inline void waitFor2(globalFlag& listenFlag,std::function<void(void)> funcOf1,std::function<void(void)> funcOf2,size_t whoIsEnd,std::function<void(void)> funcOfBegin,std::function<void(void)> funcOfEnd)
{
  static globalFlag flagOfWait2;

  size_t i=listenFlag++;

  while(i>=2)
  {
    if(listenFlag.get()<2)
    {
      i=listenFlag++;
      if(i<2)
        break;
    }
    else
      usleep(10);
  }

  // first thread
  if(i==0)
  {
    funcOf1();
  }
  // second thread
  else if(i==1)
  {
    funcOf2();
  }

  size_t tmp=flagOfWait2++;

  waitFor(flagOfWait2,[&](){},i==whoIsEnd,2);

  if(i==whoIsEnd)
  {
    while(1)
    {
      if(flagOfWait2.get()==1)
        break;
      else
        usleep(10);
    }

    funcOfEnd();
    listenFlag.reset(0);
    flagOfWait2.reset(0);
  }
  else
  {
    funcOfBegin();
    tmp=flagOfWait2++;
  }
}

#endif
