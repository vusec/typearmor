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

#ifndef _OPT_PASSCLI_H_
#define _OPT_PASSCLI_H_

#include <common/opt/llvm.h>

/* LLVM-like pass cl::opt interface (freely modified from LLVM 3.3). */

namespace cl {

class Option;

//===----------------------------------------------------------------------===//
// parser class - Parameterizable parser for different data types.  By default,
// known data types (string, int, bool) have specialized parsers, that do what
// you would expect.  The default parser, used for data types that are not
// built-in, uses a mapping table to map specific options to values, which is
// used, among other things, to handle enum types.

//--------------------------------------------------
// generic_parser_base - This class holds all the non-generic code that we do
// not need replicated for every instance of the generic parser.  This also
// allows us to put stuff into CommandLine.cpp
//
class generic_parser_base {

public:
  virtual ~generic_parser_base() {}  // Base class should have virtual-dtor
};

// Default parser implementation - This implementation depends on having a
// mapping of recognized options to values of some sort.  In addition to this,
// each entry in the mapping also tracks a help message that is printed with the
// command line option for -help.  Because this is a simple mapping parser, the
// data type can be any unsupported type.
//
template <class DataType>
class parser : public generic_parser_base {

public:
  typedef DataType parser_data_type;
};

//--------------------------------------------------
// basic_parser - Super class of parsers to provide boilerplate code
//
class basic_parser_impl {  // non-template implementation of basic_parser<t>
public:
  virtual ~basic_parser_impl() {}

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "value"; }
};

// basic_parser - The real basic parser is just a template wrapper that provides
// a typedef for the provided data type.
//
template<class DataType>
class basic_parser : public basic_parser_impl {
public:
  typedef DataType parser_data_type;
};

#define PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value) do { \
      std::stringstream ss(Arg); \
      char c; \
      ss >> Value; \
      if (ss.fail() || ss.get(c)) { \
          return true; \
      } \
      return false; \
} while(0)

//--------------------------------------------------
// parser<bool>
//
template<>
class parser<bool> : public basic_parser<bool> {
public:
  // parse - Return true on error.
  bool parse(Option &O, string ArgName, string Arg, bool &Value) {
      if (!Arg.compare(""))
          Arg="1";

      PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value);
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "bool"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<bool>);

//--------------------------------------------------
// parser<int>
//
template<>
class parser<int> : public basic_parser<int> {
public:
  // parse - Return true on error.
  bool parse(Option &O, string ArgName, string Arg, int &Value) {
      PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value);
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "int"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<int>);

//--------------------------------------------------
// parser<unsigned>
//
template<>
class parser<unsigned> : public basic_parser<unsigned> {
public:
  // parse - Return true on error.
  bool parse(Option &O, string ArgName, string Arg, unsigned &Value) {
      PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value);
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "unsigned"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<unsigned>);

//--------------------------------------------------
// parser<unsigned long long>
//
template<>
class parser<unsigned long long> : public basic_parser<unsigned long long> {
public:
  // parse - Return true on error.
  bool parse(Option &O, string ArgName, string Arg, unsigned long long &Value) {
      PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value);
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "unsigned long long"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<unsigned long long>);

//--------------------------------------------------
// parser<double>
//
template<>
class parser<double> : public basic_parser<double> {
public:
  // parse - Return true on error.
  bool parse(Option &O, string ArgName, string Arg, double &Value) {
      PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value);
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "double"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<double>);

//--------------------------------------------------
// parser<float>
//
template<>
class parser<float> : public basic_parser<float> {
public:
  // parse - Return true on error.
  bool parse(Option &O, string ArgName, string Arg, float &Value) {
      PARSER_ARG_TO_NUM_AND_RETURN(Arg, Value);
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "float"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<float>);

//--------------------------------------------------
// parser<std::string>
//
template<>
class parser<std::string> : public basic_parser<std::string> {
public:
  // parse - Return true on error.
  bool parse(Option &, string, string Arg, std::string &Value) {
    Value = Arg;
    return false;
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "string"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<std::string>);

//--------------------------------------------------
// parser<char>
//
template<>
class parser<char> : public basic_parser<char> {
public:
  // parse - Return true on error.
  bool parse(Option &, string, string Arg, char &Value) {
    Value = Arg[0];
    return false;
  }

  // getValueName - Overload in subclass to provide a better default value.
  virtual const char *getValueName() const { return "char"; }
};

EXTERN_TEMPLATE_INSTANTIATION(class basic_parser<char>);

//===----------------------------------------------------------------------===//
// Option Base class
//
class Option {

public:
  Option() {}
  virtual ~Option() {}
};

//--------------------------------------------------
// desc - Modifier to set the description shown in the -help output...
struct desc {
  const char *Desc;
  desc(const char *Str) { Desc = Str; }
};

// init - Specify a default (initial) value for the command line argument, if
// the default constructor for the argument type does not give you what you
// want.  This is only valid on "opt" arguments, not on "list" arguments.
//
template<class Ty>
struct initializer {
  const Ty Init;
  initializer(const Ty &Val) : Init(Val) {}
};

template<class Ty>
initializer<Ty> init(const Ty &Val) {
  return initializer<Ty>(Val);
}

initializer<string> init(const char *cptr) {
  std::stringstream ss;
  ss << cptr;
  return initializer<string>(ss.str());
}

//===----------------------------------------------------------------------===//
// opt - A scalar command line option.
//
template<class DataType, bool ExternalStorage = false,
          class ParserClass = parser<DataType> >
struct opt : public Option {
  ParserClass Parser;
  DataType Value;
  std::string name;
  std::string desc;

public:

  opt(const std::string &name, cl::desc desc, initializer<DataType> initValue) {
    setValue(initValue.Init);
    this->name = name;
    this->desc = desc.Desc;
    OptParam src(name, "", (Pass*) this);
    assert(OptParamParser::__OptParamParser);
    OptParam *trg;
    if (!OptParamParser::__OptParamParser->registerParam(src, &trg, false))
        return;
    typename ParserClass::parser_data_type Val =
       typename ParserClass::parser_data_type();
    if (Parser.parse(*this, trg->key, trg->value, Val))
        trg->setInvalid(); // parse error
    else
        this->setValue(Val);
  }

  DataType &operator=(const DataType &Val) {
    this->setValue(Val);
    return this->getValue();
  }

  operator DataType() const { return this->getValue(); }
  
  const DataType &getValue() const {
    return Value;
  }

  void setValue(const DataType &V) { Value = V; }
};

}

#define PASSICLI_ONCE() \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<bool>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<int>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<unsigned>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<unsigned long long>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<double>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<float>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<std::string>); \
    TEMPLATE_INSTANTIATION(class cl::basic_parser<char>);

#endif

