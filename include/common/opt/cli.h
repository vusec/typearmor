/*
 * Copyright 2017, Victor van der Veen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _OPT_CLI_H_
#define _OPT_CLI_H_

#include <common/opt/passi.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <dlfcn.h>
#include <assert.h>
#include <limits.h>

using namespace std;

class Pass;

class OptUtil
{
public:
    static void split(vector<string> &tokens, const string &text, char sep);
    static void split2(vector<vector<string> > &tokens, const string &text, const char *seps);
    static string join(vector<string> &tokens, unsigned start, unsigned end, char sep);
private:
    OptUtil() {}
};

inline void OptUtil::split(vector<string> &tokens, const string &text, char sep)
{
    int start = 0, end = 0;
    while ((end = text.find(sep, start)) != string::npos) {
      tokens.push_back(text.substr(start, end - start));
      start = end + 1;
    }
    tokens.push_back(text.substr(start));
}

inline void OptUtil::split2(vector<vector<string> > &tokens, const string &text, const char *seps)
{
    vector<string> tmpTokens;
    split(tmpTokens, text, seps[0]);
    for (unsigned i=0;i<tmpTokens.size();i++) {
        vector<string> subTokens;
        split(subTokens, tmpTokens[i], seps[1]);
        tokens.push_back(subTokens);
    }
}

inline string OptUtil::join(vector<string> &tokens, unsigned start, unsigned end, char sep)
{
    ostringstream oss;
    for (unsigned i=start;i<=end;i++) {
        if (i > start)
            oss << sep;
        oss << tokens[i];
    }
    return oss.str();
}

class OptParam
{
public:
    OptParam(string key="", string value="", Pass* owner=NULL) { this->key=key; this->value=value; this->raw=toString(); this->owner=owner; }
    bool hasKey() { return key.compare(""); }
    bool hasValue() { return value.compare(""); }
    bool hasOwner() { return owner != NULL && owner != (Pass*) -1; }
    bool isInvalid() { return owner == (Pass*) -1; }
    void setInvalid() { owner = (Pass*) -1; }
    void fromString(string &str);
    string toString() { return !hasKey() ? value : !hasValue() ? key : key + "=" + value; }
    string key;
    string value;
    string raw;
    Pass *owner;
};

inline void OptParam::fromString(string &str)
{
    raw = str;
    if (str[0] != '-' || str.size() <= 1) {
        key="";
        value=str;
        return;
    }
    vector<string> tokens;
    OptUtil::split(tokens, str, '=');
    if (tokens.size() < 1) {
        key = str;
        value = "";
        return;
    }
    key = tokens[0].substr(1);
    value = OptUtil::join(tokens, 1, tokens.size()-1, '=');
}

enum OptParamParserReqs {
  OPPR_NONE,
  OPPR_IO,
  OPPR_ARGS,
  OPPR_IO_OR_ARGS
};

class OptParamParser
{
public:
    static OptParamParser* getInstance(int argc, char **argv);
    static OptParamParser* getInstance(string &str);
    static OptParamParser* getInstance(vector<string> &strs);
    static OptParamParser* __OptParamParser;

    int parse(string &err);
    int parseParamGroup(vector<string> &paramGroup, string &err, bool force);
    void parseError(string opt, string msg, string &err);
    int parseArg(OptParam &param, string &err);
    int parseParam(vector<OptParam> &rawParams, string &err);
    int parseAndLoad(string &err, OptParamParserReqs reqs=OPPR_IO);
    int load(string &err);
    int check(string &err, OptParamParserReqs reqs);

    int registerParam(OptParam &src, OptParam **trg, bool isPass);

    vector<OptParam> getParams();
    vector<OptParam> getPasses();
    vector<string> getLoadPaths();
    string getInput();
    string getOutput();
    vector<string> getArgs();
    const char** getArgv();
    bool hasIO();

    string usage();
private:
    OptParamParser() {};
    OptParamParser(OptParamParser const&);
    void operator=(OptParamParser const&);
    int check(vector<OptParam> &list, string &err);

    vector<string> strParams;
    vector<OptParam> params;
    vector<OptParam> passes;
    vector<string> loadPaths;
    string input;
    string output;
    vector<string> args;
};

inline OptParamParser* OptParamParser::getInstance(int argc, char **argv)
{
    vector<string> strs;
    for (int i=1;i<argc;i++) {
        string s(argv[i]);
        strs.push_back(s);
    }
    return getInstance(strs);
}

inline OptParamParser* OptParamParser::getInstance(string &str)
{
    vector<string> strs;
    OptUtil::split(strs, str, ' ');
    return getInstance(strs);
}

inline OptParamParser* OptParamParser::getInstance(vector<string> &strs)
{
    __OptParamParser = new OptParamParser();
    __OptParamParser->strParams = strs;
    return __OptParamParser;
}

inline int OptParamParser::parse(string &err)
{
    vector<string> paramGroup;
    int ret;
    for (unsigned i=0;i<strParams.size();i++) {
        paramGroup.push_back(strParams[i]);
        ret = parseParamGroup(paramGroup, err, false);
        if (ret > 0) {
            unsigned count=0;
            for (unsigned j=0;j<ret-1 && i+1+j < strParams.size();j++) {
                paramGroup.push_back(strParams[i+1+j]);
                count++;
            }
            i+=count;
            ret = parseParamGroup(paramGroup, err, true);
        }
        if (ret < 0) {
            return ret;
        }
        paramGroup.clear();
    }
    return 0;
}

inline int OptParamParser::parseParamGroup(vector<string> &paramGroup, string &err, bool force)
{
    vector<OptParam> rawParams;
    int ret;
    assert(paramGroup.size() > 0);
    for (unsigned i=0;i<paramGroup.size();i++) {
        OptParam rawParam;
        rawParam.fromString(paramGroup[i]);
        rawParams.push_back(rawParam);
    }
    if (!rawParams[0].hasKey()) {
        assert(rawParams.size() == 1);
        return parseArg(rawParams[0], err);
    }
    ret = parseParam(rawParams, err);
    if (ret > 0 && force) {
        parseError("-" + rawParams[0].key, "Insufficient number of arguments", err);
        ret = -1;
    }
    return ret;
}

inline int OptParamParser::parseArg(OptParam &param, string &err)
{
    string str = param.value;
    if (input.compare("")) {
        parseError(str, "Invalid argument", err);
        return -1;
    }
    input = str;
    return 0;
}

inline int OptParamParser::parseParam(vector<OptParam> &rawParams, string &err)
{
    string key = rawParams[0].key;
    string value = rawParams[0].value;
    if (!key.compare("load")) {
        loadPaths.push_back(value);
        return 0;
    }
    if (!key.compare("args")) {
        if (rawParams.size() == 1)
            return INT_MAX;
        for (unsigned i=1;i<rawParams.size();i++)
            args.push_back(rawParams[i].raw);
        return 0;
    }
    if (!key.compare("o")) {
        if (rawParams.size() < 2) {
            return 2;
        }
        output = rawParams[1].value;
        return 0;
    }
    params.push_back(rawParams[0]);
    return 0;
}

inline void OptParamParser::parseError(string opt, string msg, string &err)
{
    err = "Bad argument: '" + opt + "' (" + msg + ")";
}

inline int OptParamParser::parseAndLoad(string &err, OptParamParserReqs reqs)
{
    int ret = parse(err);
    if (ret < 0)
        return ret;
    ret = load(err);
    if (ret < 0)
        return ret;
    return check(err, reqs);
}

inline int OptParamParser::load(string &err)
{
    void *handle;
    for (unsigned i=0;i<loadPaths.size();i++) {
        handle = dlopen(loadPaths[i].c_str(), RTLD_LAZY|RTLD_GLOBAL);
        if (!handle) {
            parseError(loadPaths[i], dlerror(), err);
            return -1;
        }
    }
    return 0;
}

inline int OptParamParser::check(string &err, OptParamParserReqs reqs)
{
    int ret = check(params, err);
    if (ret < 0)
        return ret;
    ret = check(passes, err);
    if (ret < 0)
        return ret;
    bool _hasIO = hasIO();
    bool hasArgs = args.size() > 0;
    if (!_hasIO && !hasArgs && reqs == OPPR_IO_OR_ARGS) {
        err = "Args or input+output files missing!";
        ret = -1;
    }
    else if (!_hasIO && reqs == OPPR_IO) {
        if (!input.compare("")) {
            err = "Input file missing!";
            ret = -1;
        }
        else if (!output.compare("")) {
            err = "Output file missing!";
            ret = -1;
        }
    }
    else if (!hasArgs && reqs == OPPR_ARGS) {
        err = "Args missing!";
        ret = -1;
    }
    return ret;
}

inline vector<string> OptParamParser::getLoadPaths()
{
    return loadPaths;
}

inline vector<OptParam> OptParamParser::getParams()
{
    return params;
}

inline vector<OptParam> OptParamParser::getPasses()
{
    return passes;
}

inline string OptParamParser::getInput()
{
    return input;
}

inline string OptParamParser::getOutput()
{
    return output;
}

inline vector<string> OptParamParser::getArgs()
{
    return args;
}

inline const char** OptParamParser::getArgv()
{
    const char **argv = new const char*[args.size()+1];
    for (unsigned i=0;i<args.size();i++) {
        argv[i] = args[i].c_str();
    }
    argv[args.size()] = NULL;
    return argv;
}

inline bool OptParamParser::hasIO()
{
    return input.compare("") && output.compare("");
}

inline string OptParamParser::usage()
{
    ostringstream oss;
    oss << "Usage: ... [opts] [-o <output_file> <input_file> | -args <args>]" << endl;
    oss << "Valid [opts]: " << endl;
    oss << "    -load=/path/to/plugin: Specifies plugin containing passes." << endl;
    oss << "    -pass-name: Specifies pass to run over the input file." << endl;
    return oss.str();
}

inline int OptParamParser::check(vector<OptParam> &list, string &err)
{
    for (unsigned i=0;i<list.size();i++) {
        if (!list[i].hasOwner()) {
            if (!list[i].isInvalid())
                parseError("-" + list[i].key, "Unknown argument", err);
            else
                parseError("-" + list[i].key, "Bad value '" + list[i].value  + "'", err);
            return -1;
        }
    }
    return 0;
}

int OptParamParser::registerParam(OptParam &src, OptParam **trg, bool isPass)
{
    int ret;
    if (trg)
        *trg = NULL;
    OptParam *_trg;
    for (unsigned i=0;i<passes.size();i++) {
        if (!passes[i].key.compare(src.key)) {
            if (passes[i].hasOwner())
                return -1;
            passes.erase(passes.begin()+i);
        }
    }
    for (unsigned i=0;i<params.size();i++) {
        if (!params[i].key.compare(src.key)) {
            if (params[i].hasOwner())
                return -1;
            if (isPass) {
                passes.push_back(params[i]);
                _trg = &passes[passes.size()-1];
                params.erase(params.begin()+i);
            }
            else {
                _trg = &params[i];
            }
            if (src.hasOwner())
                _trg->owner = src.owner;
            if (trg)
                *trg = _trg;
            return 1;
        }
    }
    return 0;
}

#define OPT_CLI_ONCE() \
    OptParamParser* OptParamParser::__OptParamParser = NULL; \
    std::vector<const PassTimer*> PassTimer::expiredTimers;

#endif
