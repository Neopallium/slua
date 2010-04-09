/*
  Copyright (c) 2009 Robert G. Jakabosky
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  MIT License: http://www.opensource.org/licenses/mit-license.php
*/

#ifndef slua_compiler_h
#define slua_compiler_h

#include "lua_core.h"

#define SLUA_VERSION "slua 0.4"
#define SLUA_COPYRIGHT "Copyright (C) 2008-2010 Robert G. Jakabosky"

#include "lobject.h"

int slua_compiler_main();
void slua_new_compiler(lua_State *L);
void slua_free_compiler(lua_State *L);
void slua_compiler_compile(lua_State *L, Proto *p);
void slua_compiler_compile_all(lua_State *L, Proto *p);
void slua_compiler_free(lua_State *L, Proto *p);

extern int slua_precall_jit (lua_State *L, StkId func, int nresults);
extern int slua_precall_lua (lua_State *L, StkId func, int nresults);


#endif
