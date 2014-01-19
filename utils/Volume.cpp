#include <utils/Volume.h>
#include <stdexcept>

using namespace std;
using namespace utils;

Volume::Volume(string _name,
			   string _device,
			   string key,
			   string monce,
			   string util) : name(_name), device(_device), encryptedKey(key), encryptedMonce(monce), encryptionUtil(util)
{

}

Volume::~Volume() {

}

string Volume::getSerialized() {
  throw runtime_error("not implemented");
}
