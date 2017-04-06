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

#ifndef _UTIL_FAKEID_H
#define _UTIL_FAKEID_H

#include <sys/types.h>
#include <unistd.h>

#ifdef _UTIL_FAKEID_ALL
#define _UTIL_FAKEID_GETTERS 1
#define _UTIL_FAKEID_SETTERS 1
#endif

#ifndef _UTIL_FAKEID_GID_DEFAULT
#define _UTIL_FAKEID_GID_DEFAULT 0
#endif

#ifndef _UTIL_FAKEID_EGID_DEFAULT
#define _UTIL_FAKEID_EGID_DEFAULT 0
#endif

#ifndef _UTIL_FAKEID_UID_DEFAULT
#define _UTIL_FAKEID_UID_DEFAULT 0
#endif

#ifndef _UTIL_FAKEID_EUID_DEFAULT
#define _UTIL_FAKEID_EUID_DEFAULT 0
#endif

#define __ID_ATTR __attribute__((weak))

gid_t _util_fakeid_gid __ID_ATTR = _UTIL_FAKEID_GID_DEFAULT;
gid_t _util_fakeid_egid __ID_ATTR = _UTIL_FAKEID_EGID_DEFAULT;
uid_t _util_fakeid_uid __ID_ATTR = _UTIL_FAKEID_UID_DEFAULT;
uid_t _util_fakeid_euid __ID_ATTR = _UTIL_FAKEID_EUID_DEFAULT;

#define _UTIL_FAKEID_GETTER(ID) \
    return _util_fakeid_ ## ID
#define _UTIL_FAKEID_SETTER(ID) do { \
    _util_fakeid_ ## ID = ID; \
    return 0; \
} while(0)

#ifdef _UTIL_FAKEID_GETTERS

#define getgid _util_fakeid_getgid
static inline gid_t getgid(void)
{
    _UTIL_FAKEID_GETTER(gid);
}

#define getegid _util_fakeid_getegid
static inline gid_t getegid(void)
{
    _UTIL_FAKEID_GETTER(egid);
}

#define getuid _util_fakeid_getuid
static inline uid_t getuid(void)
{
    _UTIL_FAKEID_GETTER(uid);
}

#define geteuid _util_fakeid_geteuid
static inline uid_t geteuid(void)
{
    _UTIL_FAKEID_GETTER(euid);
}

#endif

#ifdef _UTIL_FAKEID_SETTERS

#define setuid _util_fakeid_setuid
static inline int setuid(uid_t uid)
{
    _UTIL_FAKEID_SETTER(uid);
}

#define seteuid _util_fakeid_seteuid
static inline int seteuid(uid_t euid)
{
    _UTIL_FAKEID_SETTER(euid);
}

#define setgid _util_fakeid_setgid
static inline int setgid(gid_t gid)
{
    _UTIL_FAKEID_SETTER(gid);
}

#define setegid _util_fakeid_setegid
static inline int setegid(gid_t egid)
{
    _UTIL_FAKEID_SETTER(egid);
}

#endif

#endif /* _UTIL_FAKEID_H */
