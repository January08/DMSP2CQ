// Original Work copyright (c) Oleksandr Tkachenko
// Modified Work copyright (c) 2021 Microsoft Research
//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Modified by Akash Shah

#include "functionalities.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "abycore/sharing/boolsharing.h"
#include "abycore/sharing/sharing.h"
//#include "polynomials/Poly.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/common/hash_table_entry.h"
#include "HashingTables/common/hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "config.h"
#include "batch_equality.h"
#include "equality.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <unordered_set>
#include <unordered_map>
#include <cmath>
#include "table_opprf.h"

#include <openssl/sha.h>
#include <string>
#include <cstdint>
#include <numeric>
#include <NTL/ZZ.h>

#include "utils.hpp"
#include "Timer.hpp"
#include "Paillier.hpp"
#include "KA.hpp"
#include "fileReader.hpp"
#include "block.hpp"

namespace ENCRYPTO {  

// 二维数组扁平化处理成一维
template<class T>
std::vector<T> flatten(const std::vector<std::vector<T>>& data) {
    std::vector<T> flat;
    for (const auto& bucket : data) {
        flat.insert(flat.end(), bucket.begin(), bucket.end());
    }
    return flat;
}

uint64_t generate_random_number(uint64_t max_value) {
    static std::mt19937_64 rng(std::random_device{}()); // 使用设备随机数生成种子初始化
    std::uniform_int_distribution<uint64_t> dist(0, max_value);
    return dist(rng);
}

// 处理 Client 获取的 oprf 数据，size 为获取的数据个数
std::vector<uint64_t> fromClientOprfData(const std::vector<osuCrypto::block>& data,uint64_t size)
{
  std::vector<std::vector<uint64_t>> client_simple_table1(size);

  // 确保每个内部vector的初始化
  // std::cout << "Number of OTs (outer vector size): " << data.size() << std::endl;
  for (size_t i = 0; i < data.size() && i < size; ++i) {
      std::vector<uint64_t> xor_result = blockToUint64Xor(data[i]);  // 获取异或结果
      client_simple_table1[i].insert(client_simple_table1[i].end(), xor_result.begin(), xor_result.end());
      
  }
  return flatten(client_simple_table1);
}

// 处理 Server 获取的 oprf 数据，sneles 为数据个数，sbins 为数据大小
std::vector<std::vector<uint64_t>> fromServerOprfData(const std::vector<std::vector<osuCrypto::block>>& data,uint64_t sneles=8,uint64_t snbins=1)
{
  std::vector<std::vector<uint64_t>> simulated_simple_table_2(snbins);

  // 确保每个内部vector的初始化
  size_t input_index1 = 0;
  // std::cout << "Number of OTs (outer vector size): " << data.size() << std::endl;
  for (size_t i = 0; i < snbins; ++i) {
      if (i < data.size()) { // 确保不会超出 oprf_value_1 的范围
        size_t index1 = 0;
        for (const auto &blk : data[i]) {
          auto xor_result = blockToUint64Xor(blk);  
          if (index1 % sneles == 0 && index1 != 0) {//这个是输入元素个数，context.sneles
                  std::vector<uint64_t> newRow; // 创建新行
                  simulated_simple_table_2.push_back(newRow);
              }
        
            simulated_simple_table_2[i].insert(simulated_simple_table_2[i].end(), xor_result.begin(),
                                              xor_result.end());
        }
      }
  }
  return simulated_simple_table_2;
}

size_t getSharedCount(const std::vector<bool>& isShared)
{
  size_t count=0;

  for(const auto& i : isShared)
    if(!i)
      count++;

  return count;
}

// 生成随机整数的函数
int generateRandomNumber(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(min, max);
    return distrib(gen);
}

// 分割一个整数为两个部分的秘密分享
std::tuple<int, int> splitIntoShares(int number) {
    int share1 = generateRandomNumber(1, 100);
    int share2 = number - share1;
    return std::make_tuple(share1, share2);
}

// 服务端、客户端的 id 数组（协议一）
globalData<std::vector<uint64_t>> serverID;
globalData<std::vector<uint64_t>> clientID;

// 服务端拥有的数据（协议二）
globalData<std::vector<NTL::ZZ>> serverData;

// 客户端线程 oprf 的计数（协议一、二）
globalFlag Cf1,Cf2;

// 服务端线程 oprf 的计数（协议一、二）
globalFlag Sf1,Sf2;

// 用于加密的 n、g 值（协议二）
NTL::ZZ ng[2];

// 用于等待接收 n、g 的计数（协议二）
globalFlag Sf2_Ng;

// 同态加密模块（协议二）
Paillier::Paillier* paillier;

// // 客户端服务端数据（协议三）
// globalData<std::vector<uint64_t>> clientBins;
// globalData<std::vector<uint64_t>> serverBins;

// 公钥（协议三）
globalData<EVP_PKEY*> serverKeys;
// 公钥计数（协议三）
globalFlag Sf_Keys;

// 秘密分析结果累加（协议三）
globalData<int> clientResult;
// 累加计数（协议三）
globalFlag Cf_Result;

// 秘密分析结果累加（协议三）
globalData<int> serverResult;
// 累加计数（协议三）
globalFlag Sf_Result;

// 参与协商的协商者计数（协议三）
globalFlag Sf_Share;
// 是否已协商（协议三）
std::vector<std::vector<bool>> isShared;

// 协商者与被协商者下标（协议三）
size_t firstShared;
size_t secondShared;
// 协商后的密钥（协议三）
int keyOfShared;

// 是否开启一些操作以方便调试
// #define DEBUG

void run_circuit_psi(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock,osuCrypto::Channel &chl)
{
  Timer totalTime;
  Timer psmTime;
  // 记录是否为 leader、center
  bool isLeader=context.index==0?true:false;
  bool isCenter=context.index==context.n-1?true:false;

  if (context.role == CLIENT)
  {
    Timer computationTime;

    std::vector<std::vector<uint64_t>> simulated_cuckoo_table(context.cnbins);
    for (auto i = 0ull; i < inputs.size(); ++i) {
        simulated_cuckoo_table[i % context.cnbins].push_back(inputs[i]);
    }

    context.timings.hint_computation=computationTime.end();
    
    // 协议二开始时
    if(context.psm_type == PsiAnalyticsContext::PSM2)
    {
      if(isLeader)
      {
        // 生成同态加密密钥
        paillier=new Paillier::Paillier(1024);

        // ng数组中两个元素分别对应密钥的 n、g
        ng[0]=paillier->getN();
        ng[1]=paillier->getG();

        // 将 n、g 用 | 分隔，存储到 str 中
        std::stringstream ss;
        ss << ng[0]<<"|"<<ng[1];

        std::string str=ss.str();
        uint64_t len=str.size();

        // 先发送 str 的长度，再发送 str
        sock->Send(&len,sizeof(uint64_t));
        sock->Send(str.data(),sizeof(char)*len);
      }
    }
      psmTime.start();
    // 第一次 oprf
    std::vector<uint64_t> simulated_simple_table_1 = flatten(simulated_cuckoo_table);

    // 除 center 线程外，其他线程执行 oprf，并将 id 插入全局
    if(!isCenter)
    {
      auto oprf_value = ot_receiver(simulated_simple_table_1, chl, context);

      auto data=fromClientOprfData(oprf_value,context.cnbins);

      clientID.add(data,context.index);

      #ifdef DEBUG

      // write to file

      std::vector<std::vector<uint64_t>> tmp;
      tmp.push_back(fromClientOprfData(oprf_value,1));

      writeToCSV(tmp,"Client_Oprf1_"+to_string(context.index)+".csv");

      #endif

      #if 0

      std::cout<<"Client "<<to_string(context.index)<<" flag:"<<to_string(Cf1++)<<"\n";

      #else

      Cf1++;

      #endif
    }

    // 其余线程等待 center 线程执行匿名函数中的内容后，由 center 重置 Cf1
    waitFor(Cf1,[&]()
    {
      // 将 center 的 id 存入 clientID
      clientID.add(simulated_simple_table_1,context.index);
    },isCenter,context.n-1);

    // 由 center 线程执行第二次 oprf，并将数据覆盖到全局
    if(isCenter)
    {
      // n 个服务端，便有 n 行 id，用 n 个 key 进行 oprf
      auto oprf_value = ot_receiver(flatten(clientID.data()), chl, context,context.n);
      
      std::vector<std::vector<uint64_t>> data;

      for(const auto& i : oprf_value)
        data.push_back(blockToUint64Xor(i));

      for(int i=0;i<data.size();i++)
        clientID.add(data[i],i);

      #ifdef DEBUG

      // write to file

      writeToCSV(clientID.data(),"Client_Oprf2_"+to_string(context.index)+".csv");

      #endif
    }
    // 其余线程增加 Cf2 计数
    else
    {
      #if 0

      std::cout<<"Client "<<to_string(context.index)<<" flag:"<<to_string(Cf2++)<<"\n";

      #else

      Cf2++;

      #endif
    }
      
    // 其余线程等待 center 线程执行匿名函数中的内容后，由 center 重置 Cf2
    waitFor(Cf2,[=]()
    {
      ;
    },isCenter,context.n-1);

    // 由 leader 线程发送客户端数据到 leader 服务器，并接收返回的结果 num
    if(isLeader)
    {
      auto data=flatten(clientID.data());
      sock->Send(data.data(),sizeof(uint64_t)*context.n*context.cnbins);

      // 协议一接收与客户端 id 所匹配的服务端 id 的数量
      if(context.psm_type == PsiAnalyticsContext::PSM1)
      {
        uint64_t num;
        sock->Receive(&num,sizeof(num));

        std::cout<<"Leader Client Recv num : "<<num<<"\n";
      
      }
      // 协议二接收与客户端 id 所匹配的服务端 id 对应数据之和
      else if(context.psm_type == PsiAnalyticsContext::PSM2)
      {
        uint64_t len;
        sock->Receive(&len,sizeof(uint64_t));

        char* str=new char[len];
        sock->Receive(str,sizeof(char)*len);

        std::string sum_str(str);

        delete[] str;

        NTL::ZZ sum=NTL::conv<NTL::ZZ>(sum_str.c_str());

        #if 0

        std::cout<<"Leader Client Recv sum : "<<sum<<"\n";

        #endif

        // 进行解密
        Timer decryptTime;

        NTL::ZZ original_sum=Paillier::decryptNumber(sum,paillier->getN(),paillier->getLambda(),paillier->getLambdaInverse());
        
        context.timings.decrypt=decryptTime.end();

        #if 1

        std::cout<<"original_sum : "<<original_sum<<"\n";

        #endif

        delete paillier;
      }
    }
  }
  else
  {
    // 服务端
    Timer computationTime;

    std::vector<std::vector<uint64_t>> simulated_simple_table_1(context.snbins);
    size_t input_index = 0;
    for (size_t i = 0; i < context.snbins && input_index < inputs.size(); ++i) {
        // 内层循环控制每个桶的填充数量，每个桶至少有2个元素，最多4个元素
        //for (size_t j = 0; j < i % 3 + 2 && input_index < inputs.size(); ++j)
        for (size_t j = 0; j < context.sneles;++j) {
          simulated_simple_table_1[i].push_back(inputs[input_index++]);
        }
    }

    context.timings.hint_computation=computationTime.end();

    Timer encryptTime;

    // 协议二开始时，随机生成与服务器 id 对应的数据，并进行同态加密
    if(context.psm_type == PsiAnalyticsContext::PSM2)
    {
      if(isLeader)
      {
        // 接收来自 leader 客户端发来的密钥和密钥内容
        uint64_t len;
        sock->Receive(&len,sizeof(uint64_t));

        // n g
        char* str=new char[len];
        sock->Receive(str,sizeof(char)*len);
        
        std::string ng_str(str);

        delete[] str;

        // 取出 | 分隔的 n、g 字符串
        uint64_t i=ng_str.find('|');
        const std::string& n_str=ng_str.substr(0,i);
        const std::string& g_str=ng_str.substr(i+1,std::string::npos);

        // 将字符串转化为 ZZ
        ng[0]=NTL::conv<NTL::ZZ>(n_str.c_str());
        ng[1]=NTL::conv<NTL::ZZ>(g_str.c_str());
      }

      if(!isCenter)
      {
        #if 0

        std::cout<<"Server "<<to_string(context.index)<<" flag:"<<to_string(Sf2_ng++)<<"\n";

        #else

        Sf2_Ng++;

        #endif
      }
        
        
      waitFor(Sf2_Ng,[=](){},isCenter,context.n-1);

      #if 0

      std::cout<<"Server "<<to_string(context.index)<<" ng:"<<ng[0]<<" "<<ng[1]<<"\n";

      #endif

      // 同态加密
      
      std::vector<NTL::ZZ> encryptData;

      // 是否每次都重新生成数据，为 1 则不重新生成数据
      #if 1

      if(!fileExists("Server_Data_EncryptData_"+to_string(context.index)+".csv"))
      {
        std::vector<NTL::ZZ> numbers=Paillier::numbers(context.sneles);
        encryptData=Paillier::encrypt(numbers,ng[0],ng[1]);
        std::vector<std::vector<NTL::ZZ>> tmp;
        tmp.push_back(encryptData);

        writeToCSV(tmp,"Server_Data_EncryptData_"+to_string(context.index)+".csv");
      }
      else
      {
        const auto& data=readZZFromCSV("Server_Data_EncryptData_"+to_string(context.index)+".csv");
        encryptData=data[0];
      }

      #else

      std::vector<NTL::ZZ> numbers=Paillier::numbers(context.sneles);
      encryptData=Paillier::encrypt(numbers,ng[0],ng[1]);
      std::vector<std::vector<NTL::ZZ>> tmp;
      tmp.push_back(encryptData);

      #ifdef DEBUG

      writeToCSV(tmp,"Server_Data_EncryptData_"+to_string(context.index)+".csv");

      #endif

      #endif
      // 添加到 serverData
      Timer addtime;
      serverData.add(encryptData, context.index);
      context.timings.addtime=addtime.end();
      context.timings.encrypt=encryptTime.end();

    }

    Sf2++;

    std::vector<std::vector<NTL::ZZ>> dataOfPsm2;

    waitFor(
        Sf2,
        [&]() {
          dataOfPsm2=serverData.data();
        },
        isLeader, context.n);

    Timer wholeoprf;
    psmTime.start();
    // 除 center 线程外，其余线程执行 oprf，并将数据添加到全局
    if(!isCenter)
    {
      auto oprf_value = ot_sender(simulated_simple_table_1, chl, context);

      auto raw_data=fromServerOprfData(oprf_value,context.sneles,1);

      #ifdef DEBUG

      // write to file

      writeToCSV(raw_data,"Server_Oprf1_"+to_string(context.index)+".csv");

      #endif

      auto data=raw_data[0];

      serverID.add(data,context.index);

      #ifdef DEBUG

      std::cout<<"Server "<<to_string(context.index)<<" flag:"<<to_string(Sf1++)<<"\n";

      #else

      Sf1++;

      #endif
    }

    // 其余线程等待 center 线程执行匿名函数中的内容后，由 center 重置 Sf1
    waitFor(Sf1,[&]()
    {
      // 将 center 的数据存入 clientID
      serverID.add(simulated_simple_table_1[0],context.index);
    },isCenter,context.n-1);

    // 由 center 线程执行第二次 oprf，并覆盖 serverID
    if(isCenter)
    {
      // n 个服务端，n 个 key 进行 oprf，传入 n*sneles 个 id
      auto oprf_value = ot_sender(serverID.data(), chl, context, context.n);

      //
      auto data=fromServerOprfData(oprf_value,context.sneles,context.sneles);

      #ifdef DEBUG

      writeToCSV(data,"Server_Oprf2_"+to_string(context.index)+".csv");

      #endif

      // 将 oprf 后的 id 加入 serverID
      for(int i=0;i<data.size();i++)
        serverID.add(data[i],i);
    }
    // 其余线程使计数 Sf2 加一
    else
    {
      #ifdef DEBUG

      std::cout<<"Server "<<to_string(context.index)<<" flag:"<<to_string(Sf2++)<<"\n";

      #else

      Sf2++;

      #endif
    }
  

    // 其余线程等待 center 线程执行匿名函数中的内容后，由 center 重置 Sf2
    waitFor(Sf2,[=]()
    {
      // 
    },isCenter,context.n-1);

    context.timings.wholeoprf=wholeoprf.end();
    // std::cout<<"wholeoprf time is "<<wholeoprf.end()<<"\n";

    // leader 服务器逻辑
    if(isLeader)
    {
      // 接收来自客户端的数据，并取出服务端全局数据
      std::vector<uint64_t> dataOfClient(context.n*context.cnbins);
      std::vector<std::vector<uint64_t>> dataOfServer=serverID.data();

      sock->Receive(dataOfClient.data(),sizeof(uint64_t)*context.cnbins*context.n);

      #ifdef DEBUG

      writeToCSV(dataOfServer,"Server_All_ID.csv");
      writeToCSV(serverData.data(),"Server_All_EncryptData.csv");
      std::vector<std::vector<uint64_t>> tmp;
      tmp.push_back(dataOfClient);
      writeToCSV(tmp,"Client_All_ID.csv");

      #endif

      // 协议一

      if(context.psm_type == PsiAnalyticsContext::PSM1)
    
      {
        Timer search;
        uint64_t count=0;

        for(int i=0;i<dataOfClient.size();i++)
        {
          for(int j=0;j<dataOfServer.size();j++)
          {
            for(int k=0;k<dataOfServer[j].size();k++)
            {
              if(dataOfClient[i]==dataOfServer[j][k])
                count++;
            }
          }
        }


        std::cout<<"Count : "<<count<<"\n";
        // num 为返回的值，为 0、1、2 中的值，取决于 count、context.g

        uint64_t num=0;

        if(count>0&&count<=context.g)
          num=1;
        else if(count>context.g)
          num=2;

        // 发送结果给 leader 客户端
        sock->Send(&num,sizeof(num));
        context.timings.search=search.end();
        // std::cout<<"Search Time : "<<context.timings.search<<"\n";
      }
      // 协议二
      else if(context.psm_type == PsiAnalyticsContext::PSM2)
      {
        Timer search;

        NTL::ZZ sum=Paillier::encryptNumber(NTL::ZZ(0), ng[0], ng[1]);

        for(int i=0;i<dataOfClient.size();i++)
        {
          for(int j=0;j<dataOfServer.size();j++)
          {
            for(int k=0;k<dataOfServer[j].size();k++)
            {
              if(dataOfClient[i]==dataOfServer[j][k])
              {
                sum = (sum * dataOfPsm2[j][k]) % (ng[0] * ng[0]);
              }
            }
          }
        }

        #if 0

        std::cout<<"Sum : "<<sum<<"\n";

        #endif

          std::stringstream ss;
          ss << sum;

          std::string str = ss.str();
          uint64_t len = str.size();

          sock->Send(&len, sizeof(uint64_t));
          sock->Send(str.c_str(), sizeof(char) * len);

          context.timings.search = search.end();
          //std::cout << "Search Time : " << context.timings.search << "\n";
      }
    }
  }

  context.timings.psm=psmTime.end();
  context.timings.total=totalTime.end();
}

void run_circuit_psi3(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock,
  sci::NetIO* ioArr[2], osuCrypto::Channel &chl)
{
  Timer totalTime;
  Timer psmTime;
  
  // 记录是否为 leader
  bool isLeader=context.index==0?true:false;

  // 客户端和服务端线程各自的数据
  std::vector<uint64_t> client_of_bins;
  std::vector<uint64_t> server_of_bins;

  int batch_size=8;
  int party=2;
  if(context.role == 0) {
    party=1;
  }
  
  sci::OTPack<sci::NetIO> *otpackArr[2];

  //Config
  int l= (int)context.bitlen;
  int b= (int)context.radix;

  int num_cmps, rmdr;
  rmdr = context.nbins % 8;//context.nbins值为162，rmdr值为2
  num_cmps = context.nbins + rmdr;//num_cmps值为162+2=164
  int pad;
  uint64_t value;
  if(context.role == 0) {
    pad = batch_size*rmdr;
    value = S_CONST;
  } else {
    pad = rmdr;
    value = C_CONST;
  }
  uint8_t* res_shares=new uint8_t[num_cmps];

  // 与其余 n-1 个服务器协商得到的密钥，共 n-1 个，大小为 n 方便存储
  std::vector<int> keys(context.n);

  if (context.role == CLIENT) {

    Timer computationTime;

    client_of_bins.reserve(num_cmps);
    for (int i = 0; i < context.nbins; i++) 
    {
      if (i<inputs.size())
      {
        client_of_bins.push_back(inputs[i]);
      }
      else{
        client_of_bins.push_back(generate_random_number(10000));
      }
    }

    for(int i=0; i<pad; i++) {
      client_of_bins[context.nbins+i]=value;
    }

    context.timings.hint_computation=computationTime.end();

    #if 0

    std::cout<<"The Client "<<to_string(context.index) <<"'s size of client_of_bins is "<<client_of_bins.size()<<std::endl;
    std::cout<<"The Client "<<to_string(context.index) <<"'s value of num_cmps is "<<num_cmps<<std::endl;
    std::cout << "The Client "<<to_string(context.index) <<"'s value of pad is " << pad << std::endl;
    std::cout << "The Client "<<to_string(context.index) <<"'s size of context.nbins is: " << context.nbins << std::endl;

    std::vector<std::vector<uint64_t>> tmp;
    tmp.push_back(client_of_bins);
    writeToCSV(tmp,"clientBins_"+to_string(context.index)+".csv");

    #endif

    Timer baseOT;

    otpackArr[0] = new OTPack<NetIO>(ioArr[0], party, b, l);
    otpackArr[1] = new OTPack<NetIO>(ioArr[1], 3-party, b, l);

    context.timings.base_ots_sci = baseOT.end();
    
    psmTime.start();

    BatchEquality<NetIO>* compare;
    compare = new BatchEquality<NetIO>(party, l, b, batch_size, num_cmps, ioArr[0], ioArr[1], otpackArr[0], otpackArr[1]);
    perform_batch_equality(client_of_bins.data(), compare, res_shares);
  }
  else
  { 
    Timer computationTime;
    KA::KA* ka;

    server_of_bins.reserve(batch_size * num_cmps);

    // 插入数据到表中，每行有3个元素
    size_t input_index = 0;
    size_t elements_per_row = batch_size; // 每行（每组）应有的元素数

    // 直接插入数据到 client_psm1 向量中
    for (size_t i = 0; i < context.nbins; ++i) {
        for (size_t j = 0; j < elements_per_row; ++j) {
            if (input_index < inputs.size()) {
                server_of_bins.push_back(inputs[input_index++]);
            } else {
                server_of_bins.push_back(generate_random_number(1000)); // 如果输入用尽，则填充随机数
            }
        }
    }
    
    for(int i=0; i<pad; i++) {
        server_of_bins[batch_size*context.nbins+i]=value;
    }

    // std::ofstream outfile4("server_of_bins.csv"+to_string(context.index)+".csv");
    //   if (outfile4.is_open()) {
    //     for (size_t i = 0; i < server_of_bins.size(); ++i) {
    //         outfile4 << server_of_bins[i];
    //         if ((i + 1) % elements_per_row != 0) { // 在每组的最后一个元素后不添加逗号
    //             outfile4 << ", ";
    //         } else if (i + 1 != server_of_bins.size()) { // 如果不是最后一个元素，则添加换行符
    //             outfile4 << "\n";
    //         }
    //     }
    //     outfile4.close();
    //     // std::cout << "Data has been written to client_psm1.csv\n";
    // } else {
    //     // std::cerr << "Unable to open file: client_psm1.csv\n";
    // }

    // 存储是否已协商的状态数组，有 n 个
    isShared.resize(context.n);

    // 默认与其他 n-1 个服务器都是未协商状态，自身与自身之间始终为未协商状态
    for(int i=0;i<context.n;i++)
      isShared[context.index].push_back(false);

    if(isLeader)
    {
      // 由 leader 服务器获取一串公钥分发给其余服务器
      ka=new KA::KA;
      serverKeys.set(ka->keys(context.n));
    }

    Sf_Keys++;

    // 等待 leader 服务器自增完成（提交全部公钥）
    waitFor(Sf_Keys,[&](){},isLeader,context.n);

    // 各个服务器开始协商
    while(getSharedCount(isShared[context.index])!=1)
    {
      // 最多两个服务器进行交互
      waitFor2(Sf_Share,
      [&]()
      {
        firstShared=context.index;
      },
      [&]()
      {
        secondShared=context.index;
      },
      1,
      [&]()
      {
        if(!isShared[firstShared][secondShared])
        {
          #ifdef DEBUG

          std::cout<<"The first is:"<<to_string(firstShared)<<",The second is:"<<to_string(secondShared)<<"\n";
          
          #endif
          
          auto secret = KA::compute_shared_secret(serverKeys.getByPos(firstShared), serverKeys.getByPos(secondShared));
          keyOfShared=secret[0];
          keys[secondShared]=secret[0];
          isShared[firstShared][secondShared]=true;

          #ifdef DEBUG

          std::cout<<"Server "<<to_string(context.index)<<" key("<<to_string(secondShared)<<"):"<<keyOfShared<<"\n";
          
          #endif
        }
      },
      [&]()
      {
        if(!isShared[secondShared][firstShared])
        {
          keys[firstShared]=-keyOfShared;
          isShared[secondShared][firstShared]=true;

          #ifdef DEBUG

          std::cout<<"Server "<<to_string(context.index)<<" key("<<to_string(firstShared)<<"):"<<-keyOfShared<<"\n";
          
          #endif
        }
      });
    }
    // 将各个服务器获取到的 keys 输出到文件

    #if 0

    std::vector<std::vector<int>> tmp1;
    tmp1.push_back(keys);

    writeToCSV(tmp1,"Server_Keys_"+to_string(context.index)+".csv");

    #endif

    #if 1

    // std::cout<<"The Server "<<to_string(context.index) <<"'s size of server_of_bins is "<<server_of_bins.size()<<std::endl;

    context.timings.hint_computation=computationTime.end();

    std::vector<std::vector<uint64_t>> tmp2;
    tmp2.push_back(server_of_bins);
    // writeToCSV(tmp2,"serverBins_"+to_string(context.index)+".csv");

    #endif

    Timer baseOT;

    otpackArr[0] = new OTPack<NetIO>(ioArr[0], party, b, l);
    otpackArr[1] = new OTPack<NetIO>(ioArr[1], 3-party, b, l);
    
    context.timings.base_ots_sci = baseOT.end();

    psmTime.start();

    BatchEquality<NetIO>* compare;
    compare = new BatchEquality<NetIO>(party, l, b, batch_size, num_cmps, ioArr[0], ioArr[1], otpackArr[0], otpackArr[1]);
    perform_batch_equality(server_of_bins.data(), compare, res_shares);

    if(isLeader)
    {
      delete ka;
    }
  }

  std::vector<int> data(num_cmps);
  // std::string fileName=(context.role==SERVER?"dataOfServer_":"dataOfClient_")+to_string(context.index)+".csv";

  for(int i=0; i<num_cmps; i++)
  {
    data[i]=res_shares[i];
  }

  #if 1

  std::vector<std::vector<int>> tmp;
  tmp.push_back(data);
  writeToCSV(tmp,"res_share_P_"+to_string(context.role)+"_"+to_string(context.index)+".dat");

  #endif

  int result=std::accumulate(data.begin(), data.end(), 0, std::bit_xor<>());
  context.timings.psm=psmTime.end();
   

  // std::cout<<(context.role==SERVER?"Server_":"Client_")<<context.index<<"'s result is "<<result<<"\n";
  int patchOfA,patchOfB,patchOfC;

  if(context.role==SERVER)
  {
    // 定义最小和最大值
    int min = 100;
    int max = 10000;
    // 生成随机数a, b
    int a = generateRandomNumber(min, max);
    int b = generateRandomNumber(min, max);
    // 计算乘积c
    int c = a * b;
    // 分割a, b, c为秘密分享
    auto [a0, a1] = splitIntoShares(a);
    auto [b0, b1] = splitIntoShares(b);
    auto [c0, c1] = splitIntoShares(c);

    patchOfA=a1;
    patchOfB=b1;
    patchOfC=c1;

    sock->Send(&a0,sizeof(int));
    sock->Send(&b0,sizeof(int));
    sock->Send(&c0,sizeof(int));
  }
  else
  {
    sock->Receive(&patchOfA,sizeof(int));
    sock->Receive(&patchOfB,sizeof(int));
    sock->Receive(&patchOfC,sizeof(int));
  }

  // A和B各自的私有值
  int x;
  int y;

  int x0,x1;
  int y0,y1;
  int e0,e1;
  int f0,f1;

  if(context.role==SERVER)
  {
    y=result;
    y0=0;
    y1=y;
    
    sock->Send(&y0,sizeof(int));
    sock->Receive(&x1,sizeof(int));

    e1=x1-patchOfA;
    f1=y1-patchOfB;

    sock->Send(&e1,sizeof(int));
    sock->Send(&f1,sizeof(int));
    sock->Receive(&e0,sizeof(int));
    sock->Receive(&f0,sizeof(int));
  }
  else
  {
    x=result;
    x0=x;
    x1=0;

    sock->Receive(&y0,sizeof(int));
    sock->Send(&x1,sizeof(int));

    e0=x0-patchOfA;
    f0=y0-patchOfB;

    sock->Receive(&e1,sizeof(int));
    sock->Receive(&f1,sizeof(int));
    sock->Send(&e0,sizeof(int));
    sock->Send(&f0,sizeof(int));
  }

  // 计算e和f的总和
  int e = e0 + e1;
  int f = f0 + f1;

  int z0,z1;
  int endOfX,endOfY;

  if(context.role==SERVER)
  {
    z1=patchOfC+patchOfA*f+patchOfB*e;
    endOfY=y-2*z1;
    endOfY=std::accumulate(keys.begin(),keys.end(),endOfY);

    serverResult.add(endOfY,context.index);

    Sf_Result++;

    waitFor(Sf_Result,[&]()
    {
      const auto& data=serverResult.data();
      endOfY=std::accumulate(data.begin(),data.end(),0);
    },isLeader,context.n);
  }
  else
  {
    z0=patchOfC+patchOfA*f+patchOfB*e+e*f;
    endOfX=x-2*z0;

    clientResult.add(endOfX,context.index);

    Cf_Result++;

    waitFor(Cf_Result,[&]()
    {
      const auto& data=clientResult.data();
      endOfX=std::accumulate(data.begin(),data.end(),0);
    },isLeader,context.n);
  }


  
  #if 1

  if(isLeader)
  {
    if(context.role==SERVER)
    {
      sock->Send(&z1,sizeof(int));
      sock->Send(&endOfY,sizeof(int));
      sock->Receive(&z0,sizeof(int));
      sock->Receive(&endOfX,sizeof(int));
    }
    else
    {
      sock->Receive(&z1,sizeof(int));
      sock->Receive(&endOfY,sizeof(int));
      sock->Send(&z0,sizeof(int));
      sock->Send(&endOfX,sizeof(int));
    }

    // 测试乘积是否正确
    // int xy = z0 + z1;
    // std::cout<<"z0 is"<<z0<<std::endl;
    // std::cout<<"z1 is"<<z1<<std::endl;

    // // 输出结果
    // std::cout << "x: " << x << ", y: " << y << ", x * y = " << xy << std::endl;

    //测试xa+xb结果是否正确
    std::cout<<" Test Result is "<<endOfX+endOfY<<std::endl;
  }

  #if 0

  // 输出分割的秘密分享
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< "Shares of a: patchOfA = " << patchOfA << std::endl;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< "Shares of b: patchOfB = " << patchOfB << std::endl;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< "Shares of c: patchOfC = " << patchOfC << std::endl;

  #endif

  #endif

  context.timings.total=totalTime.end();
  // std::cout<<"total times is "<<context.timings.total<<std::endl;
}

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                         e_role role){
  std::unique_ptr<CSocket> socket;
  if (role == SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  return socket;
}

/*
 * Print Timings
 */
void PrintTimings(const PsiAnalyticsContext &context)
{
  // 服务端有 vrf
  if(context.role==SERVER)
  {
    std::cout << "Time for vrf " << context.timings.vrf << " ms\n";
  }

  // 仅有协议一、协议二有 oprf
  if(context.psm_type != PsiAnalyticsContext::PSM3)
  {
    std::cout << "Time for OPRF1 " << context.timings.oprf1 << " ms\n";
    std::cout << "Time for OPRF2 " << context.timings.oprf2 << " ms\n";
  }
  
  std::cout << "Time for hint computation " << context.timings.hint_computation << " ms\n";

  // 仅有协议二有同态加密
  if(context.psm_type == PsiAnalyticsContext::PSM2)
  {
    if(context.role==SERVER)
    {
      std::cout << "Time for encrypt " << context.timings.encrypt << " ms\n";
    }
    else
    {
      std::cout << "Time for decrypt " << context.timings.decrypt << " ms\n";
    }
  }
  
  // 总时间以及去掉 OT 的时间
  // std::cout << "Timing for base OT " << context.timings.base_ots_libote<< " ms\n";
  std::cout << "Timing for PSM " << context.timings.psm<< " ms\n";
  std::cout << "Total runtime " << context.timings.total<< " ms\n";
  std::cout << "Total runtime w/o base OTs:" << context.timings.totalWithoutOT<< " ms\n";
}

/*
 * Clear communication counts for new execution
 */

void ResetCommunication(std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl, PsiAnalyticsContext &context) {
    chl.resetStats();
    sock->ResetSndCnt();
    sock->ResetRcvCnt();
}

void ResetCommunication(std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl, sci::NetIO* ioArr[2], PsiAnalyticsContext &context) {
    chl.resetStats();
    sock->ResetSndCnt();
    sock->ResetRcvCnt();
    context.sci_io_start.resize(2);
		for(int i=0; i<2; i++) {
				context.sci_io_start[i] = ioArr[i]->counter;
		}
}

/*
 * Measure communication
 */
void AccumulateCommunicationPSI(std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl, PsiAnalyticsContext &context) {

  context.sentBytesOPRF = chl.getTotalDataSent();
  context.recvBytesOPRF = chl.getTotalDataRecv();

  context.sentBytesHint = sock->getSndCnt();
  context.recvBytesHint = sock->getRcvCnt();

  // 模拟服务端向 leader 发送总数据
  if(context.role==SERVER)
  {
    // 若不为 center 服务器
    if(context.index!=context.n-1)
    {
      // 统计第一次 oprf 时，各个服务器向 center 发第一次 oprf 结果的数据
      context.sentBytesHint+=sizeof(osuCrypto::block)*context.sneles;
    
      // 统计协议二中各个服务器需要额外发送给 center 的加密数据
      if(context.psm_type==context.PSM2)
        context.sentBytesHint+=sizeof(char) * 528*context.sneles;
      
      // 若为 leader 服务器
      if (context.index == 0)
      {
        // leader 接收来自 center 服务器的第二次 oprf 的数据
        context.recvBytesHint += sizeof(osuCrypto::block) * context.sneles * context.n;

        // leader 接收来自 center 的全部加密数据，减去接收的 p q 密钥（协议二）
        if (context.psm_type == context.PSM2)
        {
          context.recvBytesHint += sizeof(char) * 528 * context.sneles * context.n;
          // 减去密钥长度，第一个 uint64_t 是密钥 n、g 的长度，第二个 uint64_t 是发送结果数据的长度，context.bitlen+1 是 n、g 密钥加上一个 | 分隔符
          context.recvBytesHint -= sizeof(uint64_t) * 2 + sizeof(char) * (2*context.bitlen+1);
        }
      }
    }
    // center 服务器
    else 
    {
      // 接收来自其余 n-1 个服务器的 id 数据
      context.recvBytesHint+=sizeof(osuCrypto::block)*context.sneles*(context.n-1);
      // 向 leader 发送第二次 oprf 的数据
      context.sentBytesHint+=sizeof(osuCrypto::block)*context.sneles*context.n;
      
      // 接收其余 n-1 个服务器的加密数据、发送汇总的加密数据给 leader（协议二）
      if(context.psm_type==context.PSM2)
      {
        context.recvBytesHint+=sizeof(char) * 528*context.sneles*(context.n-1);
        context.sentBytesHint+=sizeof(char) * 528*context.sneles*context.n;
      }
    }
  }
  else
  {
    // leader 客户端

    // 协议二发送密钥长度以及密钥给 leader 服务器
    if(context.index==0 && context.psm_type==context.PSM2)
    {
      context.sentBytesHint -= sizeof(uint64_t) * 2 + sizeof(char) * (2*context.bitlen+1);
    }
  }

  context.sentBytesSCI = 0;
  context.recvBytesSCI = 0;

  //Send SCI Communication
  if (context.role == CLIENT) {
    sock->Receive(&context.recvBytesSCI, sizeof(uint64_t));
    sock->Send(&context.sentBytesSCI, sizeof(uint64_t));
  } else {
    sock->Send(&context.sentBytesSCI, sizeof(uint64_t));
    sock->Receive(&context.recvBytesSCI, sizeof(uint64_t));
  }
}

void AccumulateCommunicationPSI(std::unique_ptr<CSocket> &sock, osuCrypto::Channel &chl, sci::NetIO* ioArr[2], PsiAnalyticsContext &context) {

  context.sentBytesOPRF = chl.getTotalDataSent();
  context.recvBytesOPRF = chl.getTotalDataRecv();

  context.sentBytesHint = sock->getSndCnt();
  context.recvBytesHint = sock->getRcvCnt();

  if(context.role==SERVER)
  {
    // 减去 a、b、c
    context.sentBytes-=sizeof(int)*3;
  }
  else
  {
    context.recvBytesHint-=sizeof(int)*3;
  }

  // 协议三开销

  context.sentBytesSCI = 0;
  context.recvBytesSCI = 0;

  for(int i=0; i<2; i++) {
		context.sentBytesSCI += ioArr[i]->counter - context.sci_io_start[i];
	}

  //Send SCI Communication
  if (context.role == CLIENT) {
    sock->Receive(&context.recvBytesSCI, sizeof(uint64_t));
    sock->Send(&context.sentBytesSCI, sizeof(uint64_t));
  } else {
    sock->Send(&context.sentBytesSCI, sizeof(uint64_t));
    sock->Receive(&context.recvBytesSCI, sizeof(uint64_t));
  }
}

/*
 * Print communication
 */
void PrintCommunication(PsiAnalyticsContext &context) {
  if (context.index==context.n-1 || context.index==0 || context.index==1)
  {
  context.sentBytes = context.sentBytesOPRF + context.sentBytesHint + context.sentBytesSCI;
  context.recvBytes = context.recvBytesOPRF + context.recvBytesHint + context.recvBytesSCI;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Communication Statistics: "<<std::endl;
  double sentinMB, recvinMB;
  sentinMB = context.sentBytesOPRF/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesOPRF/((1.0*(1ULL<<20)));
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Sent Data OPRF (MB): "<<sentinMB<<std::endl;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Received Data OPRF (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytesHint/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesHint/((1.0*(1ULL<<20)));
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Sent Data Hint (MB): "<<sentinMB<<std::endl;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Received Data Hint (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytesSCI/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytesSCI/((1.0*(1ULL<<20)));
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Sent Data CryptFlow2 (MB): "<<sentinMB<<std::endl;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Received Data CryptFlow2 (MB): "<<recvinMB<<std::endl;

  sentinMB = context.sentBytes/((1.0*(1ULL<<20)));
  recvinMB = context.recvBytes/((1.0*(1ULL<<20)));
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Total Sent Data (MB): "<<sentinMB<<std::endl;
  std::cout<<(context.role==SERVER?"Server":"Client")<<" "<<to_string(context.index)<< ": Total Received Data (MB): "<<recvinMB<<std::endl;
  }
  
  
}

}
