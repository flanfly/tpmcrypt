/*
 *    This file is part of tpmcrypt.
 *
 *    tpmcrypt is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    tpmcrypt is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with tpmcrypt.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <vector>
#include <sstream>
#include <cstring>
#include <string>
#include <stdexcept>
#include <utils/KeyFile.h>
#include <unistd.h>

using namespace utils;
using namespace std;

const static string BEGIN_VOLUME = "-----BEGIN VOLUME-----";
const static string END_VOLUME = "-----END VOLUME-----";
const static string BEGIN_MONCE = "-----BEGIN MONCE-----";
const static string END_MONCE = "-----END MONCE-----";
const static string BEGIN_KEYBLOB = "-----BEGIN KEYBLOB-----";
const static string END_KEYBLOB = "-----END KEYBLOB-----";
const static string VOLUME_NAME = "Volume Name: ";
const static string DEVICE_NAME = "Device: ";
const static string TOOL_NAME = "Encryption Tool: ";

KeyFile::KeyFile(string file) :
keyFilePath(file),
keyFile(),
volumes() {
    this->parseFile();
}

KeyFile::~KeyFile() {

}

void KeyFile::parseFile() {
    string line, volumeName, deviceName, toolName;
    size_t found = 0;
    string key, monce;

    keyFile.open(keyFilePath.c_str(), ios::in);

    if (!keyFile.is_open()) {
      throw invalid_argument("Can't open file '" + keyFilePath + "'");
    }

    enum _parser_state
    {
      VOLUME_LIST = 0,
      VOLUME = 1,
      MONCE = 2,
      KEY = 3
    } pstate = VOLUME_LIST;

    while (keyFile.good()) {
      for (std::string line; std::getline(keyFile, line); ) {
        std::cout  << "Debug: " << line << ", state " << pstate << endl;
        auto i = line.find(":");


        switch(pstate)
        {
          case VOLUME_LIST:
            if(line == BEGIN_VOLUME)
              pstate = VOLUME;
            else if(!line.size())
              ;
            else
              throw invalid_argument("Read '" + line + "' while in VOLUME_LIST state");
            break;

          case VOLUME:
            if(line == BEGIN_MONCE)
              pstate = MONCE;
            else if(line == END_VOLUME)
              pstate = VOLUME_LIST;
            else if(line == BEGIN_KEYBLOB)
              pstate = KEY;
            else if(i != string::npos)
            {
              if(line.substr(0,i) == "name")
                cout << "Volume name is '" + line.substr(i) + "'" << endl;
              else if(line.substr(0,i) == "device")
                cout << "Volume device is '" + line.substr(i) + "'" << endl;
              else if(line.substr(0,i) == "util")
                cout << "Volume util is '" + line.substr(i) + "'" << endl;
              else
                throw invalid_argument("Unknown field '" + line.substr(0,i) + "'");
            }
            else if(!line.size())
              ;
            else
              throw invalid_argument("Read '" + line + "' while in VOLUME state");
            break;

          case MONCE:
            if(line == END_MONCE)
              pstate = VOLUME;
            else
              monce += line;
            break;

          case KEY:
           if(line == END_KEYBLOB)
              pstate = VOLUME;
            else
              key += line;
            break;

          default:
            throw runtime_error("Unknown parser state " + to_string(pstate));
        }
      }
  }

      if( !volumeName.empty() && !deviceName.empty() && !toolName.empty() && !key.size() && !monce.size() ) {
                volumes.push_back(Volume(volumeName, deviceName, key, toolName, monce));
        }

    keyFile.close();
}

void KeyFile::flushFile() {
    keyFile.open(keyFilePath.c_str(), ios::out | ios::trunc);

    if (!keyFile.is_open()) {

    }

    for (list<Volume>::iterator it = volumes.begin(); it != volumes.end(); ++it) {
        stringstream key, monce;

        keyFile << BEGIN_VOLUME << endl;

        keyFile << VOLUME_NAME << it->name << endl;
        keyFile << DEVICE_NAME << it->device << endl;
        keyFile << TOOL_NAME << it->encryptionUtil << endl;

        monce << it->encryptedMonce << endl;
        key << it->encryptedKey << endl;

        keyFile << BEGIN_MONCE << endl;

        while(!monce.eof()) {
            if ((monce.tellp() % 64) == 0) {
                keyFile << endl;
            }

            keyFile << (char) monce.get();
        }

        keyFile << END_MONCE << endl;
        keyFile << BEGIN_KEYBLOB << endl;

        while(!key.eof()) {
            if ((key.tellp() % 64) == 0) {
                keyFile << endl;
            }

            keyFile << (char) key.get();
        }

        keyFile << END_KEYBLOB << endl;
        keyFile << END_VOLUME << endl;
    }

    keyFile.close();
    sync();
}

void KeyFile::add(Volume vol) {
    if (searchFile(vol.name) != volumes.end()) {
        throw 1;
    }

    volumes.push_back(vol);
    flushFile();
}

void KeyFile::del(string id) {
    list<Volume>::iterator it;

    it = searchFile(id);

    if (it == volumes.end()) {
        throw 1;
    }

    volumes.erase(it);
    flushFile();
}

Volume KeyFile::get(string id) {
    list<Volume>::iterator it;

    it = searchFile(id);

    if (it == volumes.end()) {
        throw 1;
    }

    return (*it);
}

list<Volume> KeyFile::getAll() {
    return volumes;
}

list<Volume>::iterator KeyFile::searchFile(string name) {
    for (list<Volume>::iterator it = volumes.begin(); it != volumes.end(); ++it) {
        if (it->name == name) {
            return it;
        }
    }

    return volumes.end();
}
