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

#include <iostream>
#include <string>
#include <stdio.h>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include "CryptoBackend.h"
#include "TpmBackend.h"
#include "CryptSetup.h"
#include "Base64.h"
#include "KeyFile.h"

using namespace std;
using namespace crypto;
using namespace tpm;
using namespace tools;

int
main ( int argc, char** argv ) {
    SecureString<char> foo;

    foo = getPassword("Enter the password: ");

    return 0;
}

