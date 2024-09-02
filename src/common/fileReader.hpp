#ifndef FILE_READER_H
#define FILE_READER_H

#include <string>
#include <NTL/ZZ.h>
#include <iostream>


inline bool fileExists(const std::string& filename)
{
  std::ifstream file(filename);
  return file.good();
}

template<class T=uint64_t>
inline void writeToCSV(const std::vector<std::vector<T>>& data, const std::string& filename)
{
    std::ofstream file(filename);  

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    for (const auto& row : data) {
        for (size_t i = 0; i < row.size(); ++i) {
            file << row[i];
            if (i < row.size() - 1) file << ",";  
        }
        file << "\n"; 
    }

    file.close(); 
}

inline std::vector<std::vector<NTL::ZZ>> readZZFromCSV(const std::string& filename)
{
  std::vector<std::vector<NTL::ZZ>> data;

  std::ifstream file(filename);  // 打开文件

  if (!file.is_open()) {
      std::cerr << "Failed to open file: " << filename << std::endl;
      return data;
  }

  std::string line;
  while (std::getline(file, line)) {
      std::vector<NTL::ZZ> row;
      std::stringstream ss(line);
      std::string cell;

      while (std::getline(ss, cell, ','))
      {
          row.push_back(NTL::conv<NTL::ZZ>(cell.c_str()));
      }

      data.push_back(row);
  }

  file.close();  // 关闭文件

  return data;
}

#endif
