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

#ifndef PATHARMOR_ENV_H
#define PATHARMOR_ENV_H

#define pa_xstr(s) pa_str(s)
#define pa_str(s) #s
#define PATHARMOR_ROOT pa_xstr(PA_ROOT)
#define LBR_LIBSYMS PATHARMOR_ROOT"/libsyms.rel"
#define LBR_BININFO PATHARMOR_ROOT"/bin.info"

#endif /* PATHARMOR_ENV_H */

