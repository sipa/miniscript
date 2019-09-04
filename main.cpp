#include <iostream>
#include <stdio.h>
#include <string>
#include <ctype.h>
#include <assert.h>

#include <script/miniscript.h>

#include "compiler.h"

using miniscript::operator"" _mst;

static bool run(std::string&& line, int64_t count) {
    if (line.size() && line.back() == '\n') line.pop_back();
    if (line.size() == 0) return false;

    miniscript::NodeRef<std::string> ret;
    double avgcost = 0;
    if (Compile(Expand(line), ret, avgcost)) {
        std::string str;
        ret->ToString(COMPILER_CTX, str);
        printf("X %17.10f %5i %s %s\n", ret->ScriptSize() + avgcost, (int)ret->ScriptSize(), Abbreviate(std::move(str)).c_str(), line.c_str());
    } else if ((ret = miniscript::FromString(Expand(line), COMPILER_CTX))) {
        printf("%7li scriptlen=%i maxops=%i type=%s safe=%s nonmal=%s dissat=%s input=%s output=%s miniscript=%s\n", (long)count, (int)ret->ScriptSize(), (int)ret->GetOps(), ret->GetType() << "B"_mst ? "B" : ret->GetType() << "V"_mst ? "V" : ret->GetType() << "W"_mst ? "W" : ret->GetType() << "K"_mst ? "K" : "(invalid)", ret->GetType() << "s"_mst ? "yes" : "no", ret->GetType() << "m"_mst ? "yes" : "no", ret->GetType() << "f"_mst ? "no" : ret->GetType() << "e"_mst ? "unique" : ret->GetType() << "d"_mst ? "yes" : "unknown", ret->GetType() << "z"_mst ? "0" : ret->GetType() << "o"_mst ? (ret->GetType() << "n"_mst ? "1n" : "1") : ret->GetType() << "n"_mst ? "n" : "-", ret->GetType() << "u"_mst ? "1" : "nonzero", line.c_str());
    } else {
        printf("Failed to parse as policy or miniscript '%s'\n", line.c_str());
    }
    return true;
}

int main(void) {
    int64_t count = 0;
    do {
        std::string line;
        std::getline(std::cin, line);
        if (!run(std::move(line), count++)) break;
    } while(true);
}
