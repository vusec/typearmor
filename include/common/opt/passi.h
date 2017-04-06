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

#ifndef _OPT_PASSI_H_
#define _OPT_PASSI_H_

#include <ctime>
#include <common/opt/cli.h>
#include <common/opt/passcli.h>

/* LLVM-like pass interface (freely modified from LLVM 3.3). */

#define errs() cerr
#define dbgs() cout

// Different types of passes.
enum PassKind {
  PT_Module
};

//===---------------------------------------------------------------------------
/// RegisterPass<t> template - This template class is used to notify the system
/// that a Pass is available for use, and registers it into the internal
/// database maintained by the PassManager.  Unless this template is used, opt,
/// for example will not be able to see the pass and attempts to create the pass
/// will fail. This template is used in the follow manner (at global scope, in
/// your .cpp file):
///
/// static RegisterPass<YourPassClassName> tmp("passopt", "My Pass Name");
///

template<typename passName>
struct RegisterPass {
  RegisterPass(const char *PassArg, const char *Name, bool CFGOnly = false,
               bool is_analysis = false)
  {
      passName* pass = new passName();
      pass->setName(PassArg);
      OptParam src(PassArg, "", pass);
      assert(OptParamParser::__OptParamParser);
      OptParamParser::__OptParamParser->registerParam(src, NULL, true);
  }
};

//===----------------------------------------------------------------------===//
/// Pass interface - Implemented by all 'passes'.  Subclass this if you are an
/// interprocedural optimization or you do not fit into any of the more
/// constrained passes described below.
///
class Pass {
  const void *PassID;
  PassKind Kind;
  void operator=(const Pass&);
  Pass(const Pass &);

public:
  explicit Pass(PassKind K, char &pid) : PassID(&pid), Kind(K) { }
  virtual ~Pass() { }

  PassKind getPassKind() const { return Kind; }

  const std::string &getName() const { return name; }
  void setName(std::string str) { name = str; }

protected:
  std::string name;
};


//===----------------------------------------------------------------------===//
/// ModulePass class - This class is used to implement unstructured
/// interprocedural optimizations and analyses.  ModulePasses may do anything
/// they want to the program.
///
class ModulePass : public Pass {
public:
  // doInitialization - Virtual method which can be overriden by subclasses to 
  // do any initialization before a process is created or attached to
  virtual void doInitialization(){};

  /// runOnModule - Virtual method overriden by subclasses to process the module
  /// being operated on.
  virtual bool runOnModule(void *M) = 0;
  virtual bool runOnModule(void *M, std::string path, std::string pathout,
    bool &outputWritten) {
    return runOnModule(M);
  }

  explicit ModulePass(char &pid) : Pass(PT_Module, pid) {}
  virtual ~ModulePass() { }
};

/// Timer - This class is used to track the amount of time spent between
/// invocations of its startTimer()/stopTimer() methods.
///
class Timer {
  std::string Name;      // The name of this time variable.
  struct timespec time_start;
  struct timespec time_end;
  double elapsed;
public:
  explicit Timer(std::string N) { init(N); }

  // Create an uninitialized timer, client must use 'init'.
  explicit Timer() {}
  void init(std::string N) { Name=N; elapsed=0; }

  const std::string &getName() const { return Name; }
  const double getElapsed() const { return elapsed; }

  /// startTimer - Start the timer running.  Time between calls to
  /// startTimer/stopTimer is counted by the Timer class.  Note that these calls
  /// must be correctly paired.
  ///
  virtual void startTimer() {
      clock_gettime(CLOCK_MONOTONIC_RAW, &time_start);
  }

  /// stopTimer - Stop the timer.
  ///
  virtual void stopTimer() {
      struct timespec time;
      clock_gettime(CLOCK_MONOTONIC_RAW, &time_end);
      if ((time_end.tv_nsec-time_start.tv_nsec)<0) {
          time.tv_sec = time_end.tv_sec-time_start.tv_sec-1;
          time.tv_nsec = 1000000000+time_end.tv_nsec-time_start.tv_nsec;
      } else {
          time.tv_sec = time_end.tv_sec-time_start.tv_sec;
          time.tv_nsec = time_end.tv_nsec-time_start.tv_nsec;
      };
      elapsed += (double)time.tv_sec + ((double)time.tv_nsec)/1000000000;
  }

  virtual void print() const {
      errs() << Name << "_pass_secs = " << std::setiosflags(ios::fixed) << std::setprecision(3) << elapsed << std::endl;
  }
};

class PassTimer : public Timer {
public:
  virtual void stopTimer() {
      Timer::stopTimer();
      PassTimer::expiredTimers.push_back(this);
  }
  static PassTimer* getPassTimer(const std::string &name, bool timePasses) {
      return timePasses ? new PassTimer(name) : NULL;
  }
  static void printExpiredTimers() {
      for (unsigned i=0;i<expiredTimers.size();i++) {
          if (i==0)
              errs() << "[time-passes-info]" << std::endl;
          expiredTimers[i]->print();
      }
  }
  static std::vector<const PassTimer*> expiredTimers;

private:
  PassTimer(std::string N) : Timer(N) {}
};

/// The TimeRegion class is used as a helper class to call the startTimer() and
/// stopTimer() methods of the Timer class.  When the object is constructed, it
/// starts the timer specified as its argument.  When it is destroyed, it stops
/// the relevant timer.  This makes it easy to time a region of code.
///
class TimeRegion {
  Timer *T;
public:
  explicit TimeRegion(Timer &t) : T(&t) {
    T->startTimer();
  }
  explicit TimeRegion(Timer *t) : T(t) {
    if (T) T->startTimer();
  }
  ~TimeRegion() {
    if (T) T->stopTimer();
  }
};

extern cl::opt<bool> __PASS_DEBUG;
extern cl::opt<std::string> __PASS_DEBUG_PASS;

#define DEBUG(X) if (__PASS_DEBUG || !__PASS_DEBUG_PASS.getValue().compare(this->name)) { X; }

#define PASS_ONCE() \
    PASSICLI_ONCE(); \
    cl::opt<bool> \
    __PASS_DEBUG("debug", \
    cl::desc("Enables debugging for all the passes."), \
    cl::init(false)); \
    cl::opt<std::string> \
    __PASS_DEBUG_PASS("debug-pass", \
    cl::desc("Enables debugging for a specific pass."), \
    cl::init(""))

#define STD_GEN_CL_OPTS() \
    cl::opt<bool> \
    __CL_TIME_PASSES("time-passes", \
    cl::desc("Time each pass and print elapsed time."), \
    cl::init(false)); \

#endif

